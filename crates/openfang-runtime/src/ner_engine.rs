//! ONNX-based Named Entity Recognition engine for PII detection.
//!
//! Uses `ort` (ONNX Runtime) with a pre-exported NER model (e.g. `dslim/bert-base-NER`)
//! to detect person names, locations, organizations, and miscellaneous entities.
//! Only compiled when the `ner` cargo feature is active.

use ndarray::Array2;
use ort::session::Session;
use std::path::Path;
use std::sync::OnceLock;
use tokenizers::Tokenizer;
use tracing::{debug, info, warn};

/// Global singleton for the NER engine.
static GLOBAL_NER_ENGINE: OnceLock<Option<NerEngine>> = OnceLock::new();

/// A detected named entity with span information.
#[derive(Debug, Clone)]
pub struct NerEntity {
    pub entity_type: NerEntityType,
    pub text: String,
    /// Byte offset start (inclusive) in the original text.
    pub start: usize,
    /// Byte offset end (exclusive) in the original text.
    pub end: usize,
    /// Average confidence score across the entity's tokens.
    pub confidence: f32,
}

/// Entity types from the `dslim/bert-base-NER` model (CoNLL-2003 scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NerEntityType {
    Person,
    Location,
    Organization,
    Misc,
}

impl NerEntityType {
    /// Whether this entity type constitutes PII for taint tracking purposes.
    /// Only person names are treated as PII by default.
    pub fn is_pii(&self) -> bool {
        matches!(self, NerEntityType::Person)
    }

    /// Placeholder string used when redacting this entity type.
    pub fn pii_placeholder(&self) -> &'static str {
        match self {
            NerEntityType::Person => "[PERSON]",
            NerEntityType::Location => "[LOCATION]",
            NerEntityType::Organization => "[ORGANIZATION]",
            NerEntityType::Misc => "[MISC]",
        }
    }

    /// Human-readable label.
    pub fn label_str(&self) -> &'static str {
        match self {
            NerEntityType::Person => "PERSON",
            NerEntityType::Location => "LOCATION",
            NerEntityType::Organization => "ORGANIZATION",
            NerEntityType::Misc => "MISC",
        }
    }
}

/// Label map for `dslim/bert-base-NER`.
///
/// Indices: 0=O, 1=B-MISC, 2=I-MISC, 3=B-PER, 4=I-PER, 5=B-ORG, 6=I-ORG, 7=B-LOC, 8=I-LOC
const LABEL_MAP: &[&str] = &[
    "O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
];

/// Maps a BIO label index to its entity type (if not O).
fn label_to_entity_type(label_idx: usize) -> Option<(NerEntityType, bool)> {
    match label_idx {
        1 => Some((NerEntityType::Misc, true)),  // B-MISC
        2 => Some((NerEntityType::Misc, false)), // I-MISC
        3 => Some((NerEntityType::Person, true)),  // B-PER
        4 => Some((NerEntityType::Person, false)), // I-PER
        5 => Some((NerEntityType::Organization, true)),  // B-ORG
        6 => Some((NerEntityType::Organization, false)), // I-ORG
        7 => Some((NerEntityType::Location, true)),  // B-LOC
        8 => Some((NerEntityType::Location, false)), // I-LOC
        _ => None, // O
    }
}

/// ONNX-based NER inference engine.
///
/// Thread-safe (`Send + Sync`) — the `ort::Session` and `tokenizers::Tokenizer`
/// both satisfy these bounds.
pub struct NerEngine {
    session: Session,
    tokenizer: Tokenizer,
    /// Default minimum confidence threshold.
    default_confidence: f32,
}

/// Initialise the global NER engine singleton.
///
/// Must be called at most once (typically at kernel boot). If the model files
/// are missing or loading fails, the singleton is set to `None` and all
/// subsequent calls to [`global_ner_engine`] return `None`.
pub fn init_global_ner_engine(model_dir: &Path, confidence: f32) -> Result<(), String> {
    let model_path = model_dir.join("model.onnx");
    let tokenizer_path = model_dir.join("tokenizer.json");

    if !model_path.exists() {
        return Err(format!(
            "NER model file not found: {}",
            model_path.display()
        ));
    }
    if !tokenizer_path.exists() {
        return Err(format!(
            "NER tokenizer file not found: {}",
            tokenizer_path.display()
        ));
    }

    let engine = NerEngine::load(&model_path, &tokenizer_path, confidence)?;
    info!("NER engine loaded from {}", model_dir.display());

    GLOBAL_NER_ENGINE
        .set(Some(engine))
        .map_err(|_| "NER engine already initialised".to_string())
}

/// Returns a reference to the global NER engine, or `None` if not initialised
/// or if initialisation failed.
pub fn global_ner_engine() -> Option<&'static NerEngine> {
    GLOBAL_NER_ENGINE.get().and_then(|opt| opt.as_ref())
}

impl NerEngine {
    fn load(model_path: &Path, tokenizer_path: &Path, default_confidence: f32) -> Result<Self, String> {
        let session = Session::builder()
            .map_err(|e| format!("Failed to create ONNX session builder: {e}"))?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
            .map_err(|e| format!("Failed to set optimization level: {e}"))?
            .with_intra_threads(4)
            .map_err(|e| format!("Failed to set intra threads: {e}"))?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load ONNX model: {e}"))?;

        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {e}"))?;

        Ok(Self {
            session,
            tokenizer,
            default_confidence,
        })
    }

    /// Run NER inference on the input text.
    ///
    /// Returns detected entities with confidence above `min_confidence`
    /// (or the engine's default if `None` is passed).
    pub fn predict(&self, text: &str, min_confidence: Option<f32>) -> Vec<NerEntity> {
        let threshold = min_confidence.unwrap_or(self.default_confidence);

        if text.is_empty() {
            return Vec::new();
        }

        let encoding = match self.tokenizer.encode(text, false) {
            Ok(enc) => enc,
            Err(e) => {
                warn!("NER tokenization failed: {e}");
                return Vec::new();
            }
        };

        let token_ids = encoding.get_ids();
        let attention_mask = encoding.get_attention_mask();
        let type_ids = encoding.get_type_ids();
        let offsets = encoding.get_offsets();
        let seq_len = token_ids.len();

        if seq_len == 0 {
            return Vec::new();
        }

        // Build input tensors [1, seq_len]
        let input_ids = Array2::from_shape_vec(
            (1, seq_len),
            token_ids.iter().map(|&id| id as i64).collect(),
        );
        let attn_mask = Array2::from_shape_vec(
            (1, seq_len),
            attention_mask.iter().map(|&m| m as i64).collect(),
        );
        let token_type_ids = Array2::from_shape_vec(
            (1, seq_len),
            type_ids.iter().map(|&t| t as i64).collect(),
        );

        let (input_ids, attn_mask, token_type_ids) =
            match (input_ids, attn_mask, token_type_ids) {
                (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                _ => {
                    warn!("NER: failed to build input tensors");
                    return Vec::new();
                }
            };

        // Determine which inputs the model expects.
        let input_names: Vec<&str> = self
            .session
            .inputs
            .iter()
            .map(|i| i.name.as_str())
            .collect();

        let mut inputs = ort::inputs! {
            "input_ids" => input_ids.view(),
            "attention_mask" => attn_mask.view(),
        };

        // Some models (BERT) expect token_type_ids, others (DistilBERT) do not.
        if input_names.contains(&"token_type_ids") {
            inputs = ort::inputs! {
                "input_ids" => input_ids.view(),
                "attention_mask" => attn_mask.view(),
                "token_type_ids" => token_type_ids.view(),
            };
        }

        let inputs = match inputs {
            Ok(inp) => inp,
            Err(e) => {
                warn!("NER: failed to build ort inputs: {e}");
                return Vec::new();
            }
        };

        let outputs = match self.session.run(inputs) {
            Ok(out) => out,
            Err(e) => {
                warn!("NER inference failed: {e}");
                return Vec::new();
            }
        };

        // Extract logits: shape [1, seq_len, num_labels]
        let logits = match outputs[0].try_extract_tensor::<f32>() {
            Ok(tensor) => tensor,
            Err(e) => {
                warn!("NER: failed to extract logits: {e}");
                return Vec::new();
            }
        };

        let logits_shape = logits.shape();
        if logits_shape.len() != 3 || logits_shape[0] != 1 {
            warn!("NER: unexpected logits shape: {:?}", logits_shape);
            return Vec::new();
        }
        let num_labels = logits_shape[2];
        let logits_slice = logits.as_slice().unwrap_or_default();
        if logits_slice.is_empty() {
            return Vec::new();
        }

        // Reshape to [seq_len, num_labels] and apply softmax
        let logits_2d = match Array2::from_shape_vec(
            (seq_len, num_labels),
            logits_slice.to_vec(),
        ) {
            Ok(arr) => arr,
            Err(e) => {
                warn!("NER: logits reshape failed: {e}");
                return Vec::new();
            }
        };

        let probs = softmax(&logits_2d);

        // BIO decode
        decode_bio_tags(&probs, offsets, text, threshold)
    }
}

/// Per-row softmax: exp(x - max) / sum(exp(x - max)).
fn softmax(logits: &Array2<f32>) -> Array2<f32> {
    let mut result = logits.clone();
    for mut row in result.rows_mut() {
        let max_val = row.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        row.mapv_inplace(|v| (v - max_val).exp());
        let sum: f32 = row.iter().sum();
        if sum > 0.0 {
            row.mapv_inplace(|v| v / sum);
        }
    }
    result
}

/// Decode BIO-tagged token predictions into entity spans.
fn decode_bio_tags(
    probs: &Array2<f32>,
    offsets: &[(usize, usize)],
    text: &str,
    min_confidence: f32,
) -> Vec<NerEntity> {
    let seq_len = probs.nrows();
    let num_labels = probs.ncols();
    let mut entities = Vec::new();

    // Current entity state
    let mut current_type: Option<NerEntityType> = None;
    let mut current_start: usize = 0;
    let mut current_end: usize = 0;
    let mut confidence_sum: f32 = 0.0;
    let mut confidence_count: usize = 0;

    for i in 0..seq_len {
        let (off_start, off_end) = offsets[i];

        // Skip special tokens ([CLS], [SEP], [PAD]) which have offset (0, 0)
        if off_start == 0 && off_end == 0 && i > 0 {
            continue;
        }
        // Also skip the first token if it's a special token
        if off_start == 0 && off_end == 0 && i == 0 {
            continue;
        }

        // Find argmax label
        let row = probs.row(i);
        let (best_idx, &best_prob) = row
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        if best_idx >= num_labels {
            continue;
        }

        match label_to_entity_type(best_idx) {
            Some((etype, is_begin)) => {
                if is_begin || current_type != Some(etype) {
                    // Finalise previous entity
                    finalize_entity(
                        &mut entities,
                        &current_type,
                        current_start,
                        current_end,
                        confidence_sum,
                        confidence_count,
                        text,
                        min_confidence,
                    );
                    // Start new entity
                    current_type = Some(etype);
                    current_start = off_start;
                    current_end = off_end;
                    confidence_sum = best_prob;
                    confidence_count = 1;
                } else {
                    // Continue current entity (I-tag, same type)
                    current_end = off_end;
                    confidence_sum += best_prob;
                    confidence_count += 1;
                }
            }
            None => {
                // O tag — finalise any open entity
                finalize_entity(
                    &mut entities,
                    &current_type,
                    current_start,
                    current_end,
                    confidence_sum,
                    confidence_count,
                    text,
                    min_confidence,
                );
                current_type = None;
                confidence_sum = 0.0;
                confidence_count = 0;
            }
        }
    }

    // Finalise last entity if any
    finalize_entity(
        &mut entities,
        &current_type,
        current_start,
        current_end,
        confidence_sum,
        confidence_count,
        text,
        min_confidence,
    );

    debug!("NER detected {} entities", entities.len());
    entities
}

#[allow(clippy::too_many_arguments)]
fn finalize_entity(
    entities: &mut Vec<NerEntity>,
    entity_type: &Option<NerEntityType>,
    start: usize,
    end: usize,
    confidence_sum: f32,
    confidence_count: usize,
    text: &str,
    min_confidence: f32,
) {
    if let Some(etype) = entity_type {
        if confidence_count > 0 && start < end && end <= text.len() {
            let avg_confidence = confidence_sum / confidence_count as f32;
            if avg_confidence >= min_confidence {
                entities.push(NerEntity {
                    entity_type: *etype,
                    text: text[start..end].to_string(),
                    start,
                    end,
                    confidence: avg_confidence,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_softmax_basic() {
        let logits =
            Array2::from_shape_vec((1, 3), vec![1.0, 2.0, 3.0]).unwrap();
        let result = softmax(&logits);
        let row = result.row(0);
        let sum: f32 = row.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        // Largest logit should have highest probability
        assert!(row[2] > row[1]);
        assert!(row[1] > row[0]);
    }

    #[test]
    fn test_softmax_uniform() {
        let logits =
            Array2::from_shape_vec((2, 4), vec![0.0; 8]).unwrap();
        let result = softmax(&logits);
        for row in result.rows() {
            for &val in row.iter() {
                assert!((val - 0.25).abs() < 1e-5);
            }
        }
    }

    #[test]
    fn test_label_to_entity_type() {
        assert!(label_to_entity_type(0).is_none()); // O
        assert_eq!(
            label_to_entity_type(3),
            Some((NerEntityType::Person, true))
        ); // B-PER
        assert_eq!(
            label_to_entity_type(4),
            Some((NerEntityType::Person, false))
        ); // I-PER
        assert_eq!(
            label_to_entity_type(7),
            Some((NerEntityType::Location, true))
        ); // B-LOC
        assert_eq!(
            label_to_entity_type(8),
            Some((NerEntityType::Location, false))
        ); // I-LOC
        assert!(label_to_entity_type(9).is_none()); // out of range
    }

    #[test]
    fn test_ner_entity_type_is_pii() {
        assert!(NerEntityType::Person.is_pii());
        assert!(!NerEntityType::Location.is_pii());
        assert!(!NerEntityType::Organization.is_pii());
        assert!(!NerEntityType::Misc.is_pii());
    }

    #[test]
    fn test_ner_entity_type_placeholders() {
        assert_eq!(NerEntityType::Person.pii_placeholder(), "[PERSON]");
        assert_eq!(NerEntityType::Location.pii_placeholder(), "[LOCATION]");
        assert_eq!(
            NerEntityType::Organization.pii_placeholder(),
            "[ORGANIZATION]"
        );
        assert_eq!(NerEntityType::Misc.pii_placeholder(), "[MISC]");
    }

    #[test]
    fn test_label_map_consistency() {
        // Verify LABEL_MAP has 9 entries matching the dslim/bert-base-NER model
        assert_eq!(LABEL_MAP.len(), 9);
        assert_eq!(LABEL_MAP[0], "O");
        assert_eq!(LABEL_MAP[3], "B-PER");
        assert_eq!(LABEL_MAP[4], "I-PER");
        assert_eq!(LABEL_MAP[7], "B-LOC");
        assert_eq!(LABEL_MAP[8], "I-LOC");
    }

    #[test]
    fn test_decode_bio_tags_empty() {
        let probs = Array2::from_shape_vec((0, 9), vec![]).unwrap();
        let offsets: Vec<(usize, usize)> = vec![];
        let entities = decode_bio_tags(&probs, &offsets, "", 0.5);
        assert!(entities.is_empty());
    }

    #[test]
    fn test_decode_bio_tags_single_person() {
        // Simulate: [CLS] John [SEP]
        // Token 0: CLS (offset 0,0) -> O
        // Token 1: "John" (offset 0,4) -> B-PER with high confidence
        // Token 2: SEP (offset 0,0) -> O
        let mut probs_data = vec![0.0f32; 3 * 9];
        // Token 0 (CLS): label O (idx 0) = 0.99
        probs_data[0] = 0.99;
        // Token 1: label B-PER (idx 3) = 0.95
        probs_data[9 + 3] = 0.95;
        // Token 2 (SEP): label O (idx 0) = 0.99
        probs_data[18] = 0.99;

        let probs = Array2::from_shape_vec((3, 9), probs_data).unwrap();
        let offsets = vec![(0, 0), (0, 4), (0, 0)];
        let text = "John";

        let entities = decode_bio_tags(&probs, &offsets, text, 0.5);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity_type, NerEntityType::Person);
        assert_eq!(entities[0].text, "John");
        assert_eq!(entities[0].start, 0);
        assert_eq!(entities[0].end, 4);
        assert!(entities[0].confidence > 0.9);
    }

    #[test]
    fn test_decode_bio_tags_multi_token_entity() {
        // Simulate: [CLS] New York [SEP]
        // Token 0: CLS -> O
        // Token 1: "New" (0,3) -> B-LOC 0.90
        // Token 2: "York" (4,8) -> I-LOC 0.88
        // Token 3: SEP -> O
        let mut probs_data = vec![0.0f32; 4 * 9];
        probs_data[0] = 0.99; // CLS -> O
        probs_data[9 + 7] = 0.90; // Token 1 -> B-LOC
        probs_data[18 + 8] = 0.88; // Token 2 -> I-LOC
        probs_data[27] = 0.99; // SEP -> O

        let probs = Array2::from_shape_vec((4, 9), probs_data).unwrap();
        let offsets = vec![(0, 0), (0, 3), (4, 8), (0, 0)];
        let text = "New York";

        let entities = decode_bio_tags(&probs, &offsets, text, 0.5);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity_type, NerEntityType::Location);
        assert_eq!(entities[0].text, "New York");
        assert_eq!(entities[0].start, 0);
        assert_eq!(entities[0].end, 8);
    }

    #[test]
    fn test_decode_bio_tags_confidence_filter() {
        // Entity with low confidence should be filtered out
        let mut probs_data = vec![0.0f32; 3 * 9];
        probs_data[0] = 0.99;
        probs_data[9 + 3] = 0.3; // B-PER with low confidence
        probs_data[18] = 0.99;

        let probs = Array2::from_shape_vec((3, 9), probs_data).unwrap();
        let offsets = vec![(0, 0), (0, 4), (0, 0)];
        let text = "John";

        let entities = decode_bio_tags(&probs, &offsets, text, 0.5);
        assert!(entities.is_empty());
    }
}
