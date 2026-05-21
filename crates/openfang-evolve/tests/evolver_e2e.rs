//! End-to-end test of the evolver pipeline with canned LLM responses.
//!
//! Exercises: prompt build → sentinel parse → patch apply (all 3 formats)
//! → validation → snapshot. No real LLM driver — `send_message` is a closure
//! that returns predetermined response strings.

use openfang_evolve::evolver::{evolve, parse_evolver_response};
use openfang_evolve::types::{
    EvolutionContext, SkillCategory, SkillLineage, SkillOrigin, SkillRecord, SkillVisibility,
    SuggestionKind,
};
use openfang_types::config::EvolveConfig;
use std::collections::HashMap;
use std::fs;

fn make_parent_skill(dir: &std::path::Path) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("SKILL.md"),
        "---\nname: \"docker\"\ndescription: \"Docker ops guide\"\n---\n\n# Docker\n\nStep 1: Use port 8080\nStep 2: Done\n",
    )
    .unwrap();
}

fn parent_record(name: &str, path: &str) -> SkillRecord {
    SkillRecord {
        skill_id: format!("{name}__imp_abcdef01"),
        name: name.into(),
        description: "test".into(),
        path: path.into(),
        is_active: true,
        category: SkillCategory::ToolGuide,
        tags: vec![],
        visibility: SkillVisibility::Private,
        creator_id: "system".into(),
        lineage: SkillLineage {
            origin: SkillOrigin::Imported,
            generation: 0,
            parent_skill_ids: vec![],
            source_task_id: None,
            change_summary: String::new(),
            content_diff: String::new(),
            content_snapshot: HashMap::new(),
            pre_fix_snapshot: HashMap::new(),
            created_at: chrono::Utc::now(),
            created_by: "human".into(),
        },
        tool_dependencies: vec![],
        critical_tools: vec![],
        total_selections: 0,
        total_applied: 0,
        total_completions: 0,
        total_fallbacks: 0,
        first_seen: chrono::Utc::now(),
        last_updated: chrono::Utc::now(),
        is_canary: false,
        canary_selections: 0,
        canary_completions: 0,
        parent_completion_rate_at_birth: 0.0,
        canary_parent_skill_id: None,
    }
}

#[test]
fn parse_evolver_response_search_replace() {
    let r = "CHANGE_SUMMARY: fix step 1\n\n<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE\n<EVOLUTION_COMPLETE>";
    let out = parse_evolver_response(r).unwrap();
    assert_eq!(out.change_summary, "fix step 1");
    assert!(out.raw_content.contains("SEARCH"));
}

#[tokio::test]
async fn evolve_fix_with_search_replace() {
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("docker");
    make_parent_skill(&skill_dir);

    let parent = parent_record("docker", skill_dir.to_str().unwrap());
    let context = EvolutionContext {
        evolution_type: SuggestionKind::Fix,
        target_skills: vec![parent],
        direction: "Use the correct port".into(),
        category: None,
        trigger_context: "test".into(),
        source_analysis: None,
    };

    let response = "CHANGE_SUMMARY: Updated port from 8080 to 9090\n\n<<<<<<< SEARCH\nStep 1: Use port 8080\n=======\nStep 1: Use port 9090\n>>>>>>> REPLACE\n<EVOLUTION_COMPLETE>";
    let cfg = EvolveConfig::default();
    let result = evolve(&context, &cfg, &skill_dir, |_msg| {
        let r = response.to_string();
        async move { Ok((r, 100, 50)) }
    })
    .await
    .expect("evolve should succeed");

    assert!(result.success);
    assert!(result
        .content_snapshot
        .get("SKILL.md")
        .unwrap()
        .contains("port 9090"));
    assert!(!result
        .content_snapshot
        .get("SKILL.md")
        .unwrap()
        .contains("port 8080"));
}

#[tokio::test]
async fn evolve_captured_full_content() {
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("captured-deadbeef");

    let context = EvolutionContext {
        evolution_type: SuggestionKind::Captured,
        target_skills: vec![],
        direction: "Capture debugging pattern".into(),
        category: Some(SkillCategory::Workflow),
        trigger_context: "agent solved novel task".into(),
        source_analysis: None,
    };

    let response = "CHANGE_SUMMARY: Captured debugging workflow\n\n*** Begin Files\n*** File: SKILL.md\n---\nname: \"debug-flow\"\ndescription: \"Generic debugging\"\n---\n\n# Debug Flow\n\n1. Reproduce\n2. Isolate\n3. Fix\n*** End Files\n\n<EVOLUTION_COMPLETE>";
    let cfg = EvolveConfig::default();
    let result = evolve(&context, &cfg, &skill_dir, |_msg| {
        let r = response.to_string();
        async move { Ok((r, 100, 50)) }
    })
    .await
    .expect("evolve should succeed");

    assert!(result.success);
    assert!(result
        .content_snapshot
        .get("SKILL.md")
        .unwrap()
        .contains("Debug Flow"));
    assert!(skill_dir.join("SKILL.md").exists());
}

#[tokio::test]
async fn evolve_failure_sentinel_propagates() {
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("dummy");

    let context = EvolutionContext {
        evolution_type: SuggestionKind::Captured,
        target_skills: vec![],
        direction: "x".into(),
        category: None,
        trigger_context: "x".into(),
        source_analysis: None,
    };

    let response = "<EVOLUTION_FAILED>\nNot a reusable pattern.";
    let cfg = EvolveConfig::default();
    let result = evolve(&context, &cfg, &skill_dir, |_msg| {
        let r = response.to_string();
        async move { Ok((r, 50, 25)) }
    })
    .await;
    assert!(result.is_err(), "EVOLUTION_FAILED should propagate as Err");
}

#[tokio::test]
async fn evolve_exhausts_iterations_without_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let skill_dir = tmp.path().join("dummy");

    let context = EvolutionContext {
        evolution_type: SuggestionKind::Captured,
        target_skills: vec![],
        direction: "x".into(),
        category: None,
        trigger_context: "x".into(),
        source_analysis: None,
    };

    // Reply that never includes a sentinel → loop should exhaust.
    let cfg = EvolveConfig {
        max_iterations: 3,
        ..Default::default()
    };
    let result = evolve(&context, &cfg, &skill_dir, |_msg| {
        async move { Ok(("still thinking".to_string(), 10, 5)) }
    })
    .await;
    assert!(result.is_err(), "should exhaust iterations");
}
