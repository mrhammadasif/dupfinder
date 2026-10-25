use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};

use axum::extract::{Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::scanner::{self, DuplicateGroup, ScanOptions, ScanResult, ScanStats};

const INDEX_HTML: &str = include_str!("ui/index.html");
const TOKEN_PLACEHOLDER: &str = "__DUPFINDER_TOKEN__";
const TOKEN_HEADER: &str = "x-dupfinder-token";

type ApiResult<T> = Result<T, (StatusCode, String)>;

pub struct ServeOptions {
    pub roots: Vec<PathBuf>,
    pub scan: ScanOptions,
    pub port: u16,
    pub open_browser: bool,
}

struct Library {
    roots: Vec<PathBuf>,
    groups: Vec<DuplicateGroup>,
    stats: ScanStats,
}

struct AppState {
    scan_options: ScanOptions,
    /// Required on every mutating request. A custom header forces a CORS preflight,
    /// so other websites open in the browser cannot trigger deletes on this server.
    token: String,
    /// Guards against DNS rebinding: only requests addressed to our own origin are served.
    allowed_hosts: Vec<String>,
    library: RwLock<Library>,
    /// Serializes deletes and rescans so the "keep at least one copy" check cannot race.
    mutation: Mutex<()>,
}

impl AppState {
    fn path_of(&self, id: usize) -> Option<PathBuf> {
        let library = self.library.read().expect("library lock poisoned");
        library
            .groups
            .iter()
            .flat_map(|g| &g.files)
            .find(|f| f.id == id)
            .map(|f| f.path.clone())
    }

    fn check_token(&self, headers: &HeaderMap) -> ApiResult<()> {
        match headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()) {
            Some(token) if token == self.token => Ok(()),
            _ => Err((StatusCode::FORBIDDEN, "Missing or invalid token".into())),
        }
    }
}

pub async fn serve(options: ServeOptions, scan: ScanResult) -> anyhow::Result<()> {
    let listener = match TcpListener::bind(("127.0.0.1", options.port)).await {
        Ok(listener) => listener,
        Err(err) if options.port != 0 => {
            eprintln!("Port {} unavailable ({err}), picking a free one", options.port);
            TcpListener::bind(("127.0.0.1", 0)).await?
        }
        Err(err) => return Err(err.into()),
    };
    let port = listener.local_addr()?.port();

    let state = Arc::new(AppState {
        scan_options: options.scan,
        token: random_token(),
        allowed_hosts: vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")],
        library: RwLock::new(Library {
            roots: options.roots,
            groups: scan.groups,
            stats: scan.stats,
        }),
        mutation: Mutex::new(()),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/groups", get(groups))
        .route("/api/file/{id}", get(file))
        .route("/api/delete", post(delete))
        .route("/api/reveal", post(reveal))
        .route("/api/rescan", post(rescan))
        .route("/api/pick-folder", post(pick_folder))
        .layer(middleware::from_fn_with_state(state.clone(), require_local_host))
        .with_state(state);

    let url = format!("http://127.0.0.1:{port}/");
    println!("Review duplicates at {url}  (Ctrl+C to quit)");
    if options.open_browser
        && let Err(err) = open::that(&url)
    {
        eprintln!("Could not open a browser ({err}); open the URL above manually.");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn random_token() -> String {
    rand::random::<[u8; 16]>().iter().map(|b| format!("{b:02x}")).collect()
}

async fn require_local_host(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| state.allowed_hosts.iter().any(|allowed| allowed == host));
    if !host_ok {
        return (StatusCode::FORBIDDEN, "Forbidden host").into_response();
    }
    next.run(req).await
}

async fn index(State(state): State<Arc<AppState>>) -> Html<String> {
    Html(INDEX_HTML.replace(TOKEN_PLACEHOLDER, &state.token))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LibraryView {
    roots: Vec<String>,
    files_seen: usize,
    bytes_seen: u64,
    unreadable: usize,
    groups: Vec<GroupView>,
}

#[derive(Serialize)]
struct GroupView {
    hash: String,
    size: u64,
    files: Vec<FileView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileView {
    id: usize,
    path: String,
    root: usize,
    name: String,
    /// Parent directory relative to the file's scan root ("" when directly inside it).
    dir: String,
    modified: Option<u64>,
    kind: &'static str,
}

async fn groups(State(state): State<Arc<AppState>>) -> Json<LibraryView> {
    let library = state.library.read().expect("library lock poisoned");
    let groups = library
        .groups
        .iter()
        .map(|g| GroupView {
            hash: g.hash.clone(),
            size: g.size,
            files: g
                .files
                .iter()
                .map(|f| {
                    let relative = f.path.strip_prefix(&library.roots[f.root]).unwrap_or(&f.path);
                    FileView {
                        id: f.id,
                        path: f.path.to_string_lossy().into_owned(),
                        root: f.root,
                        name: f
                            .path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        dir: relative
                            .parent()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        modified: f.modified,
                        kind: preview_kind(&f.path),
                    }
                })
                .collect(),
        })
        .collect();

    Json(LibraryView {
        roots: library.roots.iter().map(|r| r.to_string_lossy().into_owned()).collect(),
        files_seen: library.stats.files_seen,
        bytes_seen: library.stats.bytes_seen,
        unreadable: library.stats.unreadable,
        groups,
    })
}

fn preview_kind(path: &Path) -> &'static str {
    const TEXT_EXTENSIONS: &[&str] = &[
        "txt", "md", "json", "csv", "tsv", "log", "xml", "yml", "yaml", "toml", "ini", "cfg", "conf", "rs", "js", "ts",
        "jsx", "tsx", "vue", "py", "rb", "go", "java", "kt", "cs", "c", "h", "cpp", "hpp", "swift", "sh", "zsh",
        "bash", "sql", "css", "scss", "html", "htm", "svg",
    ];
    let mime = mime_guess::from_path(path).first();
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match mime.as_ref().map(|m| (m.type_().as_str(), m.subtype().as_str())) {
        Some(("image", "svg")) => "text",
        Some(("image", _)) => "image",
        Some(("video", _)) => "video",
        Some(("audio", _)) => "audio",
        Some(("application", "pdf")) => "pdf",
        Some(("text", _)) => "text",
        _ if TEXT_EXTENSIONS.contains(&extension.as_str()) => "text",
        _ => "other",
    }
}

/// Streams a scanned file for previews. Only ids from the current scan are accepted, so
/// arbitrary paths can never be requested. Supports Range requests (video seeking).
async fn file(State(state): State<Arc<AppState>>, UrlPath(id): UrlPath<usize>, req: Request) -> Response {
    let Some(path) = state.path_of(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let is_pdf = preview_kind(&path) == "pdf";

    let mut response = match ServeFile::new(&path).oneshot(req).await {
        Ok(response) => response.into_response(),
        Err(never) => match never {},
    };
    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Scanned HTML/SVG files must not run scripts with this app's origin (and its delete API).
    // Chrome's PDF viewer refuses to render under a sandbox CSP, and PDFs cannot script it anyway.
    if !is_pdf {
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox"));
    }
    response
}

#[derive(Deserialize)]
struct IdsRequest {
    ids: Vec<usize>,
}

#[derive(Serialize)]
struct DeleteResponse {
    deleted: Vec<usize>,
    failed: Vec<DeleteFailure>,
}

#[derive(Serialize)]
struct DeleteFailure {
    id: usize,
    path: String,
    error: String,
}

/// Moves the requested files to the system Trash. Refuses the whole request if it would
/// remove every copy in any group, so at least one copy of each file always survives.
async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<IdsRequest>,
) -> ApiResult<Json<DeleteResponse>> {
    state.check_token(&headers)?;
    let _guard = state.mutation.lock().await;

    let targets = {
        let library = state.library.read().expect("library lock poisoned");
        plan_deletion(&library.groups, &body.ids).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?
    };

    let outcomes = tokio::task::spawn_blocking(move || {
        targets
            .into_iter()
            .map(|(id, path)| {
                let result = trash::delete(&path);
                (id, path, result)
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(internal_error)?;

    let mut response = DeleteResponse {
        deleted: Vec::new(),
        failed: Vec::new(),
    };
    for (id, path, result) in outcomes {
        match result {
            Ok(()) => response.deleted.push(id),
            Err(err) => response.failed.push(DeleteFailure {
                id,
                path: path.to_string_lossy().into_owned(),
                error: err.to_string(),
            }),
        }
    }

    let mut library = state.library.write().expect("library lock poisoned");
    for group in &mut library.groups {
        group.files.retain(|f| !response.deleted.contains(&f.id));
    }
    library.groups.retain(|g| g.files.len() > 1);
    Ok(Json(response))
}

fn plan_deletion(groups: &[DuplicateGroup], ids: &[usize]) -> Result<Vec<(usize, PathBuf)>, String> {
    let mut requested: HashMap<usize, bool> = ids.iter().map(|&id| (id, false)).collect();
    let mut targets = Vec::new();

    for group in groups {
        let selected: Vec<_> = group.files.iter().filter(|f| requested.contains_key(&f.id)).collect();
        if selected.is_empty() {
            continue;
        }
        if selected.len() == group.files.len() {
            let name = group.files[0].path.file_name().unwrap_or_default().to_string_lossy();
            return Err(format!(
                "Refusing to delete every copy of \"{name}\"; keep at least one."
            ));
        }
        for file in selected {
            requested.insert(file.id, true);
            targets.push((file.id, file.path.clone()));
        }
    }

    if let Some((unknown, _)) = requested.iter().find(|(_, found)| !**found) {
        return Err(format!("Unknown file id {unknown}; rescan and try again."));
    }
    Ok(targets)
}

#[derive(Deserialize)]
struct IdRequest {
    id: usize,
}

async fn reveal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<IdRequest>,
) -> ApiResult<StatusCode> {
    state.check_token(&headers)?;
    let path = state
        .path_of(body.id)
        .ok_or((StatusCode::NOT_FOUND, "Unknown file id".to_string()))?;
    tokio::task::spawn_blocking(move || reveal_in_file_manager(&path))
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn reveal_in_file_manager(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg("-R").arg(path).status()?;
    #[cfg(target_os = "windows")]
    let status = Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(path.parent().unwrap_or(path)).status()?;

    // explorer.exe exits non-zero even on success, so only trust the status elsewhere.
    if cfg!(not(target_os = "windows")) && !status.success() {
        return Err(io::Error::other(format!("file manager exited with {status}")));
    }
    Ok(())
}

#[derive(Serialize)]
struct PickFolderResponse {
    /// `None` when the user cancelled the dialog.
    path: Option<String>,
}

/// Opens the OS-native folder picker on the machine running the server (it is always local).
async fn pick_folder(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<PickFolderResponse>> {
    state.check_token(&headers)?;
    let output = tokio::task::spawn_blocking(folder_picker_command)
        .await
        .map_err(internal_error)?
        .map_err(|err| {
            (
                StatusCode::NOT_IMPLEMENTED,
                format!("No folder picker available ({err}); type the path instead."),
            )
        })?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(Json(PickFolderResponse {
        path: (output.status.success() && !path.is_empty()).then_some(path),
    }))
}

fn folder_picker_command() -> io::Result<std::process::Output> {
    #[cfg(target_os = "macos")]
    return Command::new("osascript")
        .args([
            "-e",
            r#"POSIX path of (choose folder with prompt "Choose a folder to scan for duplicates")"#,
        ])
        .output();
    #[cfg(all(unix, not(target_os = "macos")))]
    return Command::new("zenity")
        .args(["--file-selection", "--directory"])
        .output();
    #[cfg(not(unix))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"));
}

#[derive(Deserialize)]
struct RescanRequest {
    /// New set of folders to scan; omitted means "rescan the current folders".
    roots: Option<Vec<String>>,
}

async fn rescan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RescanRequest>,
) -> ApiResult<StatusCode> {
    state.check_token(&headers)?;
    let _guard = state.mutation.lock().await;

    let roots = match body.roots {
        Some(raw) => resolve_roots(&raw).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?,
        None => state.library.read().expect("library lock poisoned").roots.clone(),
    };

    let scan_options = state.scan_options.clone();
    let scan_roots = roots.clone();
    let scan = tokio::task::spawn_blocking(move || scanner::find_duplicates(&scan_roots, &scan_options))
        .await
        .map_err(internal_error)?;

    *state.library.write().expect("library lock poisoned") = Library {
        roots,
        groups: scan.groups,
        stats: scan.stats,
    };
    Ok(StatusCode::NO_CONTENT)
}

/// Canonicalizes user-supplied folder paths (expanding a leading `~`), rejecting anything
/// that is not an existing directory and dropping duplicates.
pub fn resolve_roots(raw: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for input in raw {
        let trimmed = input.trim();
        let expanded = match (trimmed.strip_prefix('~'), std::env::var_os("HOME")) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                PathBuf::from(home).join(rest.trim_start_matches('/'))
            }
            _ => PathBuf::from(trimmed),
        };
        let canonical = expanded.canonicalize().map_err(|err| format!("\"{trimmed}\": {err}"))?;
        if !canonical.is_dir() {
            return Err(format!("\"{trimmed}\" is not a folder"));
        }
        if !roots.contains(&canonical) {
            roots.push(canonical);
        }
    }
    if roots.is_empty() {
        return Err("Add at least one folder to scan".into());
    }
    Ok(roots)
}

fn internal_error(err: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::FileEntry;

    fn group(ids: &[usize]) -> DuplicateGroup {
        DuplicateGroup {
            hash: "h".into(),
            size: 10,
            files: ids
                .iter()
                .map(|&id| FileEntry {
                    id,
                    path: PathBuf::from(format!("/f{id}")),
                    root: 0,
                    modified: None,
                })
                .collect(),
        }
    }

    #[test]
    fn plan_deletion_allows_removing_all_but_one_copy() {
        let groups = [group(&[0, 1, 2]), group(&[3, 4])];
        let targets = plan_deletion(&groups, &[1, 2, 4]).unwrap();
        let ids: Vec<_> = targets.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, [1, 2, 4]);
    }

    #[test]
    fn plan_deletion_refuses_to_remove_every_copy() {
        let groups = [group(&[0, 1]), group(&[2, 3])];
        let err = plan_deletion(&groups, &[0, 2, 3]).unwrap_err();
        assert!(err.contains("every copy"));
    }

    #[test]
    fn plan_deletion_rejects_unknown_ids() {
        let groups = [group(&[0, 1])];
        assert!(plan_deletion(&groups, &[0, 99]).unwrap_err().contains("Unknown"));
    }

    #[test]
    fn resolve_roots_validates_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file.txt");
        std::fs::write(&file, b"x").unwrap();
        let dir_str = dir.path().to_string_lossy().into_owned();

        let roots = resolve_roots(&[dir_str.clone(), format!("{dir_str}/")]).unwrap();
        assert_eq!(roots.len(), 1);

        assert!(
            resolve_roots(&[file.to_string_lossy().into_owned()])
                .unwrap_err()
                .contains("not a folder")
        );
        assert!(resolve_roots(&[format!("{dir_str}/missing")]).is_err());
        assert!(resolve_roots(&[]).is_err());
    }

    #[test]
    fn preview_kind_maps_common_extensions() {
        assert_eq!(preview_kind(Path::new("a.JPG")), "image");
        assert_eq!(preview_kind(Path::new("a.mp4")), "video");
        assert_eq!(preview_kind(Path::new("a.mp3")), "audio");
        assert_eq!(preview_kind(Path::new("a.pdf")), "pdf");
        assert_eq!(preview_kind(Path::new("a.rs")), "text");
        assert_eq!(preview_kind(Path::new("a.svg")), "text");
        assert_eq!(preview_kind(Path::new("a.zip")), "other");
    }
}
