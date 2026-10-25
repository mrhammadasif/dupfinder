# dupfinder

Rust CLI that finds duplicate files (by content) across one or more folders and serves a local
browser UI to preview and trash them.

## Run / test / build

```sh
cargo run --release -- ~/Pictures /Volumes/Backup          # scan + open UI at http://127.0.0.1:7878
cargo run --release -- ~/code -e target -e ios/Pods         # skip folders by name or trailing path
cargo run --release -- ~/Downloads --list                   # print groups, no UI
cargo test                                                   # unit tests (tempfile fixtures)
cargo clippy --all-targets && cargo fmt                      # rustfmt.toml: max_width = 120
```

## Layout

- `src/main.rs` — clap CLI, initial scan, starts the tokio runtime.
- `src/scanner.rs` — duplicate detection (sync, rayon-parallel). Pure; all tests live here.
- `src/server.rs` — axum server: `/api/groups`, `/api/file/{id}` (Range-capable previews),
  `/api/delete`, `/api/rescan`, `/api/reveal`, `/api/pick-folder`.
- `src/ui/index.html` — the whole UI (vanilla JS, no CDN), embedded with `include_str!`.

## Detection algorithm

1. Walk roots (no symlink following); skip OS junk (`.DS_Store`, `._*`, …), the always-skipped
   folders in `IGNORED_DIRS` (`.git`, `.hg`, `.svn`, `node_modules`, `android/build`; entries match
   trailing path components via `Path::ends_with`) and `--exclude` entries (same matching);
   dedupe by path and by (dev, inode) so overlapping roots and hard links never show as duplicates.
2. Group by size (metadata only).
3. Incremental hashing: rounds of 4 KiB, 32 KiB, 256 KiB … capped at 64 MiB per round; each
   round hashes the next chunk and splits groups by a chained BLAKE3 digest
   (`BLAKE3(prev_digest || chunk)`, 32 bytes of state per file). Files leave as soon as they're
   unique; every byte is read at most once. The group "hash" is this chained fingerprint, **not**
   the plain BLAKE3 of the file.

## Safety invariants (keep these)

- Bind `127.0.0.1` only; `Host` header must be `127.0.0.1:<port>`/`localhost:<port>` (DNS rebinding).
- Mutating endpoints require the `x-dupfinder-token` header (random per run, injected into the page).
- `/api/file/{id}` only serves ids from the current scan; responses carry `CSP: sandbox` (except PDFs)
  so scanned HTML/SVG can't script the app's origin.
- Delete = move to system Trash (`trash` crate), and the server refuses any request that would
  remove every copy in a group (`plan_deletion`). Deletes/rescans are serialized by a mutex.
- UI renders user data via text nodes only (filenames are untrusted).

## Known limits

- The UI loads all groups in one JSON payload; very large result sets (100k+ groups) need
  `--exclude` or server-side pagination.
- No persistent hash cache between runs.
