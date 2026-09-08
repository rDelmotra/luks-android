//! RAII Scratch Fixture Isolation.
//!
//! Provides unique, collision-proof temporary file paths under `target/scratch/`
//! (or `$LUKS_SCRATCH_DIR`), with automatic cleanup on `Drop` unless explicitly
//! preserved or when `LUKS_KEEP_FAILED_SCRATCH=1` is set.
//!
//! # Safety & Concurrency
//! Every fixture incorporates:
//! 1. A global atomic sequence counter
//! 2. The host process ID (`std::process::id()`)
//! 3. Monotonic nanosecond timestamp
//!
//! This completely eliminates file collisions during parallel test execution.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct ScratchFixture {
    path: PathBuf,
    keep_on_drop: bool,
}

impl ScratchFixture {
    /// Create a new scratch image by copying a source fixture from `fixtures/<rel_fixture_path>`.
    ///
    /// The scratch file is created in an isolated run directory under `target/scratch/`.
    pub fn new(rel_fixture_path: &str, test_context: &str) -> Self {
        let scratch_dir = Self::scratch_dir();
        std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let file_name = Path::new(rel_fixture_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("image.img");

        let sanitized_context = test_context
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();

        let dst = scratch_dir.join(format!("{sanitized_context}_{pid}_{seq}_{nanos}_{file_name}"));

        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("fixtures")
            .join(rel_fixture_path);

        assert!(
            src.exists(),
            "Source fixture missing at {:?}. Run tools/provision-fixtures.sh to generate required fixtures.",
            src
        );

        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!("failed to copy fixture {:?} to {:?}: {}", src, dst, e)
        });

        let keep_env = std::env::var("LUKS_KEEP_FAILED_SCRATCH")
            .map(|v| v == "1")
            .unwrap_or(false);

        Self {
            path: dst,
            keep_on_drop: keep_env,
        }
    }

    /// Create an empty scratch file of `size_bytes` filled with zeroes.
    pub fn new_empty(name: &str, size_bytes: u64, test_context: &str) -> Self {
        let scratch_dir = Self::scratch_dir();
        std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let sanitized_context = test_context
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();

        let dst = scratch_dir.join(format!("{sanitized_context}_{pid}_{seq}_{nanos}_{name}"));

        let file = std::fs::File::create(&dst)
            .unwrap_or_else(|e| panic!("failed to create empty scratch file {:?}: {}", dst, e));
        file.set_len(size_bytes)
            .unwrap_or_else(|e| panic!("failed to set empty scratch file length {:?}: {}", dst, e));

        let keep_env = std::env::var("LUKS_KEEP_FAILED_SCRATCH")
            .map(|v| v == "1")
            .unwrap_or(false);

        Self {
            path: dst,
            keep_on_drop: keep_env,
        }
    }

    /// Path to the scratch file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly preserve the scratch file on disk when this guard is dropped.
    ///
    /// Call this when a test detects a failure condition and wants to leave
    /// forensic evidence for inspection.
    pub fn preserve(&mut self) {
        self.keep_on_drop = true;
    }

    fn scratch_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("LUKS_SCRATCH_DIR") {
            return PathBuf::from(dir);
        }

        let run_id = std::env::var("LUKS_TEST_RUN_ID")
            .unwrap_or_else(|_| format!("run-{}", std::process::id()));

        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("scratch")
            .join(run_id)
    }
}

impl Drop for ScratchFixture {
    fn drop(&mut self) {
        if !self.keep_on_drop && self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
