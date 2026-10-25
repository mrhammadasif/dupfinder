use std::collections::HashMap;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bump whenever the chunk schedule or digest format changes, so stale caches are discarded.
const CACHE_VERSION: u32 = 1;

/// Everything that changes when a file's contents could have changed. Mirrors what git trusts
/// for its index: ctime can't be set from userspace, so `touch -m` tricks still invalidate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    inode: u64,
    device: u64,
}

impl FileStamp {
    #[cfg(unix)]
    pub fn from_metadata(meta: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileStamp {
            size: meta.size(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
            inode: meta.ino(),
            device: meta.dev(),
        }
    }

    #[cfg(not(unix))]
    pub fn from_metadata(meta: &Metadata) -> Self {
        let nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i64);
        FileStamp {
            size: meta.len(),
            modified: (nanos, 0),
            changed: (0, 0),
            inode: 0,
            device: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedFile {
    stamp: FileStamp,
    /// Chained digest after each hashing round; `digests[r]` covers the first r+1 chunks.
    digests: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct CacheContents {
    version: u32,
    files: HashMap<String, CachedFile>,
}

/// Borrowing twin of `CacheContents` (identical encoding) so saving doesn't clone the map.
#[derive(Serialize)]
struct CacheContentsRef<'a> {
    version: u32,
    files: &'a HashMap<String, CachedFile>,
}

/// Per-file chunk digests persisted between runs, so unchanged files are never re-read.
pub struct DigestCache {
    location: PathBuf,
    files: HashMap<String, CachedFile>,
}

impl DigestCache {
    pub fn default_location() -> Option<PathBuf> {
        dirs::cache_dir().map(|dir| dir.join("dupfinder").join("digests.bin"))
    }

    /// Loads the cache, starting empty if it is missing, unreadable or from another version.
    pub fn load(location: &Path) -> Self {
        let files = fs::read(location)
            .ok()
            .and_then(|bytes| postcard::from_bytes::<CacheContents>(&bytes).ok())
            .filter(|contents| contents.version == CACHE_VERSION)
            .map(|contents| contents.files)
            .unwrap_or_default();
        DigestCache {
            location: location.to_path_buf(),
            files,
        }
    }

    /// Digests recorded for this file, if it hasn't changed since they were recorded.
    pub fn digests(&self, path: &Path, stamp: &FileStamp) -> Option<&[[u8; 32]]> {
        let cached = self.files.get(path.to_str()?)?;
        (cached.stamp == *stamp).then_some(cached.digests.as_slice())
    }

    pub fn record(&mut self, path: &Path, stamp: FileStamp, digests: Vec<[u8; 32]>) {
        if let Some(key) = path.to_str() {
            self.files.insert(key.to_owned(), CachedFile { stamp, digests });
        }
    }

    /// Drops entries under `roots` that this scan didn't see (deleted or moved files).
    pub fn forget_missing(&mut self, roots: &[PathBuf], seen: &dyn Fn(&str) -> bool) {
        self.files
            .retain(|path, _| seen(path) || !roots.iter().any(|root| Path::new(path).starts_with(root)));
    }

    /// Writes atomically (temp file + rename), readable only by the current user.
    pub fn save(&self) -> io::Result<()> {
        let bytes = postcard::to_stdvec(&CacheContentsRef {
            version: CACHE_VERSION,
            files: &self.files,
        })
        .map_err(io::Error::other)?;
        if let Some(parent) = self.location.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.location.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&temp)?.write_all(&bytes)?;
        fs::rename(&temp, &self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_invalidates_on_stamp_change() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        fs::write(&file, b"one").unwrap();
        let stamp = FileStamp::from_metadata(&fs::metadata(&file).unwrap());
        let location = dir.path().join("cache/digests.bin");

        let mut cache = DigestCache::load(&location);
        cache.record(&file, stamp.clone(), vec![[7; 32]]);
        cache.save().unwrap();

        let reloaded = DigestCache::load(&location);
        assert_eq!(reloaded.digests(&file, &stamp), Some(&[[7u8; 32]][..]));

        fs::write(&file, b"two").unwrap();
        let changed = FileStamp::from_metadata(&fs::metadata(&file).unwrap());
        assert!(reloaded.digests(&file, &changed).is_none());
    }

    #[test]
    fn corrupt_cache_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let location = dir.path().join("digests.bin");
        fs::write(&location, b"not a cache").unwrap();
        assert!(DigestCache::load(&location).files.is_empty());
    }

    #[test]
    fn forget_missing_only_prunes_inside_scanned_roots() {
        let mut cache = DigestCache {
            location: PathBuf::new(),
            files: HashMap::new(),
        };
        let stamp = FileStamp::from_metadata(&fs::metadata(".").unwrap());
        for path in ["/scan/kept", "/scan/gone", "/elsewhere/file"] {
            cache.record(Path::new(path), stamp.clone(), Vec::new());
        }

        cache.forget_missing(&[PathBuf::from("/scan")], &|path| path == "/scan/kept");

        let mut left: Vec<_> = cache.files.keys().cloned().collect();
        left.sort();
        assert_eq!(left, ["/elsewhere/file", "/scan/kept"]);
    }
}
