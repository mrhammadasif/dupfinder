# dupfinder

Rust CLI that finds duplicate files (by content) across one or more folders and serves a local
browser UI to preview and trash them.

## Run / test / build

```sh
cargo run --release -- ~/Pictures /Volumes/Backup          # scan + open UI at http://127.0.0.1:7878/?t=<key>
cargo run --release -- ~/code -e target -e ios/Pods         # skip folders by name or trailing path
cargo run --release -- ~/Downloads --list                   # print groups, no UI
cargo run --release -- ~/Downloads --list --no-cache        # ignore/skip the digest cache
cargo test                                                   # unit tests (tempfile fixtures)
cargo clippy --all-targets && cargo fmt                      # rustfmt.toml: max_width = 120
```

## Layout

- `src/main.rs` — clap CLI, sizes the rayon pool (3× cores, I/O-bound), initial scan, tokio runtime.
- `src/scanner.rs` — duplicate detection (sync, rayon-parallel) + `same_contents` byte compare.
- `src/cache.rs` — persistent per-file chunk digests (`~/Library/Caches/dupfinder/digests.bin`,
  postcard, mode 0600, atomic write). Bump `CACHE_VERSION` if the chunk schedule changes.
- `src/server.rs` — axum server: `/api/groups`, `/api/file/{id}` (Range-capable previews),
  `/api/delete`, `/api/rescan`, `/api/reveal`, `/api/pick-folder`.
- `src/ui/index.html` — the whole UI (vanilla JS, no CDN), embedded with `include_str!`.

## Detection algorithm

1. Parallel walk (`rayon::scope`, one task per directory; no symlink following); skip OS junk (`.DS_Store`, `._*`, …), the always-skipped
   folders in `IGNORED_DIRS` (`.git`, `.hg`, `.svn`, `node_modules`, `android/build`; entries match
   trailing path components via `Path::ends_with`) and `--exclude` entries (same matching);
   dedupe by path and by (dev, inode) so overlapping roots and hard links never show as duplicates.
2. Group by size (metadata only).
3. Incremental hashing: rounds of 64 KiB, 1 MiB, 16 MiB, then 64 MiB chunks; each round hashes
   the next chunk and splits groups by a chained BLAKE3 digest (`BLAKE3(prev_digest || chunk)`).
   Files leave as soon as they're unique; every byte is read at most once. The group "hash" is
   this chained fingerprint, **not** the plain BLAKE3 of the file.
4. Every round's digest is cached per file, keyed by path and validated by a stamp (size, mtime,
   ctime, inode, device — like git's index). Unchanged files cost zero reads on rescans.

## Safety invariants (keep these)

- Bind `127.0.0.1` only; `Host` header must be `127.0.0.1:<port>`/`localhost:<port>` (DNS rebinding).
- Auth: a random per-run token is only in the URL the browser is opened with (`/?t=…`); the server
  swaps it for an `HttpOnly; SameSite=Strict` cookie (`dupfinder_<port>`) and every route requires
  it, so other local users/processes reaching the port get 401. The token is never in page HTML.
- Every POST also needs the `x-dupfinder` header (forces a CORS preflight, which is never granted).
- File ids are never reused across rescans (`Library::new` offsets by `next_id`), so stale pages
  or tabs get "Unknown file id" instead of hitting a different file.
- Page CSP: nonce-only inline script/style (`__CSP_NONCE__` placeholder), `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`. Don't add inline handlers/`style=` attributes or external resources.
- `/api/file/{id}` only serves ids from the current scan; responses carry `CSP: sandbox` (except PDFs)
  so scanned HTML/SVG can't script the app's origin.
- Delete = move to system Trash (`trash` crate), and the server refuses any request that would
  remove every copy in a group (`plan_deletion`). Right before trashing, `verify_duplicate` checks
  both paths are still regular files with no symlink in the path (canonicalize == path), are
  different inodes, and are byte-identical; non-UTF-8 names are refused (trash re-encodes them).
  Deletes/rescans are serialized by a mutex.
- Files are opened with `O_NONBLOCK` + an fstat regular-file check (`open_regular`), so a FIFO
  swapped in after the walk can't hang a scan or delete.
- Requests with `Sec-Fetch-Site` other than `same-origin`/`none` are rejected, and file responses
  carry `Cross-Origin-Resource-Policy: same-origin` (stops other sites embedding/probing previews).
- UI renders user data via text nodes only (filenames are untrusted); `h()` escapes bidi control
  characters in all text/titles so names can't visually disguise themselves.

## Known limits

- The UI loads all groups in one JSON payload; very large result sets (100k+ groups) need
  `--exclude` or server-side pagination.
- The digest cache stores every hashed candidate's path (~190 MB for ~700k candidates).

## Performance reference (~/projects: 817k files, 61 GB, 35 GB of real duplicates read)

- Fresh scan 30 s (was 57 s with sequential walkdir + 4 KiB×8 schedule); cached rescan 8 s.
