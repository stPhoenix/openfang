---
name: youtube-extract-skill
version: "0.1.0"
description: "Expert knowledge for extracting transcripts, metadata, and structured insights from YouTube videos via yt-dlp auto-captions"
runtime: prompt_only
---

# YouTube Info Extraction — Expert Knowledge

This hand pulls **text** out of YouTube videos: transcripts, metadata, summaries, Q&A, knowledge-graph entities. It does NOT produce video files or clips — for that, use the `clip` hand.

Subtitles are the **only** transcription source — manual (uploader-provided) preferred when present, auto-captions used as fallback. There is no Whisper / STT fallback by design. If a video has neither manual subs nor auto-captions, the hand fails fast and clearly.

## Daemon-in-Docker Note

The bundled OpenFang images (`Dockerfile`, `Dockerfile.dev`, `Dockerfile.dev-runner`, and `tests/integration/Dockerfile.daemon`) ship the yt-dlp standalone binary at `/usr/local/bin/yt-dlp` — no extra setup needed for the standard compose flows.

If you run a custom image, install yt-dlp with the upstream-recommended standalone binary method (per <https://github.com/yt-dlp/yt-dlp/wiki/Installation>):

```dockerfile
RUN curl -fsSL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp \
      -o /usr/local/bin/yt-dlp \
 && chmod a+rx /usr/local/bin/yt-dlp
```

Pin a release tag (e.g. `releases/download/2024.12.13/yt-dlp`) for reproducible builds. To update inside a running container: `yt-dlp -U`.

If yt-dlp is missing, the `[[requires]]` check blocks activation and the dashboard shows the install hint.

---

## yt-dlp Reference

### Metadata only (no captions, no video download)
```
yt-dlp --skip-download --write-info-json --no-write-subs --no-playlist -o '%(id)s' '<URL>'
```
**Single-line only.** The kernel sandbox blocks shell metacharacters: no `\n` line continuations, no `;`, `|`, `&`, `&&`, `>`, `<`, `${VAR}`, `$(...)`, backticks, `{...}`. Apply this to every yt-dlp invocation below.
Reads to `<video_id>.info.json`. Key fields:
- `id`, `title`, `uploader`, `channel`, `duration`, `description`
- `chapters` — array of `{start_time, end_time, title}` (often empty)
- `upload_date`, `view_count`, `tags`, `categories`
- `is_live`, `live_status`, `age_limit`
- `automatic_captions` — map of language code → caption track URLs (presence = available)

### Subtitles in json3 (manual preferred, auto fallback, word-level timing)
```
yt-dlp --skip-download --write-subs --write-auto-subs --sub-langs en --sub-format json3 --no-playlist -o '%(id)s' '<URL>'
```
Both flags together: yt-dlp downloads manual subs when available, falls back to auto-captions otherwise. Output filename is the same in both cases (`<video_id>.en.json3`) — to identify which was used, inspect `info.json` (`subtitles[lang]` non-empty → manual; else `automatic_captions[lang]` non-empty → auto).

Format:
```json
{
  "events": [
    {
      "tStartMs": 1230,
      "dDurationMs": 500,
      "segs": [
        { "utf8": "hello ", "tOffsetMs": 0 },
        { "utf8": "world", "tOffsetMs": 200 }
      ]
    }
  ]
}
```
Convert to segment list:
- `start_sec = tStartMs / 1000.0`
- `end_sec = (tStartMs + dDurationMs) / 1000.0`
- `text = "".join(seg.utf8 for seg in segs)`

### Listing subtitle availability
```
yt-dlp --list-subs '<URL>'
```
Lists both manual and auto-generated tracks per language. Alternatively, the metadata-fetch step already populates both `subtitles` and `automatic_captions` in `info.json` — prefer reading those instead of issuing a second yt-dlp call.

### Playlist enumeration (cost guard)
```
yt-dlp --flat-playlist --print 'id,title' '<URL>'
```
Shows entries without fetching each. ALWAYS confirm with the user before processing a multi-entry playlist — costs scale linearly.

---

## URL Forms Accepted

| Form | Example |
|------|---------|
| Standard | `https://www.youtube.com/watch?v=dQw4w9WgXcQ` |
| Short | `https://youtu.be/dQw4w9WgXcQ` |
| Shorts | `https://www.youtube.com/shorts/<id>` |
| Playlist | `https://www.youtube.com/playlist?list=<id>` |

Reject anything outside these patterns. For non-YouTube hosts (Vimeo, Twitter, etc.), refer the user to the `clip` hand which handles 1000+ sites for video downloads.

---

## Hard Refusals

| Condition | Response |
|-----------|----------|
| `is_live: true` or `live_status: is_live`/`is_upcoming` | "Live streams not supported." |
| `age_limit > 0` or yt-dlp returns auth error | "Video requires authentication. Cookie handling not supported in this hand." |
| Both `subtitles` and `automatic_captions` empty in `info.json` | "No subtitles available (no manual or auto-generated tracks). yt-dlp subs-only mode has no transcription fallback." |

---

## Chunking Long Transcripts

Auto-captions for a 1h video produce ~10-15k tokens. Past ~30k tokens, single-pass summarization quality degrades.

Strategy:
1. **If `chapters` exists and len ≥ 3** — use chapter boundaries.
2. **Else** — split by 10-minute (600s) windows on `start_sec`.
3. Summarize each chunk independently with the active `summary_style` template.
4. Merge: take chunk summaries as input, produce final document with cross-chunk synthesis.

Force chunking when `duration > 7200` sec (2h) regardless of the toggle.

---

## Output Path Conventions

All file ops are sandboxed to the agent's workspace (path injected into the system prompt under `## Workspace`). Writes outside the workspace are denied with `Access denied: path '...' resolves outside workspace`. Always use **workspace-relative paths** with `file_write` / `file_read` / `file_list` — the kernel resolves them under the workspace root automatically.

Persistent files (only when `save_transcript_file = true`):
```
transcripts/<video_id>.json   ← workspace-relative
```

Working-directory artifacts (yt-dlp writes them to CWD, which equals the workspace root; delete after Phase 5):
```
<video_id>.info.json
<video_id>.<lang>.json3
```

Do NOT pass `~`, `$HOME`, or absolute paths like `/root/.openfang/...` to file tools — they resolve outside the workspace and the sandbox rejects them.

---

## Quality Caveats to Surface

Always include in the report:
- `source` marker — `youtube-manual-subs` (uploader-provided, generally accurate) or `youtube-auto-caption` (machine-generated, may contain errors).
- Warning if any segment has zero duration or repeated tokens.
- Warning if the transcript looks under-sized for the duration (e.g., 5 minutes of segments for a 60-minute video — speaker may have been silent or captions broke).

Manual subs are usually clean (uploader took the time to write them) but can be partial, edited for clarity, or out of sync. Auto-captions are imperfect — common failure modes: missed proper nouns, run-on sentences, garbled overlapping speech.

For non-English videos with English summary requested AND auto-caption source, note that the summary is a translation of machine-generated captions — double the noise floor. For manual-subs source, the noise floor is much lower.

---

## Anti-Bot Failure Recovery

If yt-dlp returns `Sign in to confirm you're not a bot` or similar:
1. Tell the user to update yt-dlp — anti-bot signatures shift weekly. Use the same channel they installed it from:
   - Standalone binary: `yt-dlp -U` (self-update), or re-download from the GitHub releases page.
   - Homebrew: `brew upgrade yt-dlp`
   - apt/dnf/pacman: distro upgrade (often lags upstream — switch to standalone binary if so).
2. If updating doesn't help, this hand cannot proceed — `--cookies-from-browser` is intentionally unsupported here for security/portability reasons.
