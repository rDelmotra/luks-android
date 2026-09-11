//! Proves `Secret`'s memory is actually zeroed on drop (Pass N.7).
//!
//! `notes/feature-remediation.md` §4, item N.7:
//!
//! > K.5's zeroize test asserts a **mock's** `.close()`, not that `Secret`'s
//! > `ZeroizeOnDrop` ran — precisely the test the plan named and rejected. A
//! > JVM unit test structurally cannot prove this. Move the assertion to the
//! > Rust side, on the real drop path.
//!
//! The Kotlin `LuksSessionTest` K.5 idle-timeout test plugs an
//! `AutoCloseable` stub into `LuksSession` and asserts `.close()` was
//! invoked. That is real coverage of the *timer*, but it cannot reach past
//! the JNI boundary into the native heap, so it cannot see whether the
//! decrypted master key was ever scrubbed — only that some Kotlin object's
//! `close()` method ran. This test proves the property the plan actually
//! asked for, on the real `Secret` type, via its real `Drop` impl.
//!
//! # Why this needs `unsafe`, and why it isn't in `core/src/secret.rs`
//!
//! `core/src/lib.rs` has `#![forbid(unsafe_code)]` for the whole `luks_core`
//! crate, so this cannot live in `secret.rs`'s own `#[cfg(test)]` module —
//! `forbid` cannot be locally overridden by an `#[allow]`, by design. Files
//! under `core/tests/` are compiled as separate crates that merely depend
//! on `luks_core`; they are not covered by that attribute, which is why the
//! proof lives here instead.
//!
//! # Why a capturing allocator instead of reading freed memory
//!
//! The obvious first instinct — drop the `Secret`, then read through a raw
//! pointer to the now-freed buffer — was tried first and rejected: it is
//! UB (reading memory after `dealloc`), and in practice on this machine it
//! was **flaky in exactly the direction that matters**. With
//! `ZeroizeOnDrop` removed entirely (bytes never touched before the `Vec`
//! frees them), a bare post-free pointer read sometimes still showed all
//! zeros — not because anything zeroed the data, but because of what
//! happened to occupy that address next. A test that can pass on broken
//! code is worse than no test.
//!
//! This version instead installs a `#[global_alloc]` that intercepts every
//! `dealloc` call in this test binary. When it sees the deallocation of the
//! exact allocation the test is watching, it copies the buffer's contents
//! *before* handing the pointer back to the system allocator. That read is
//! not UB — the memory is still live and owned by the allocation at that
//! point — and it captures precisely the state `Secret`'s fields were in
//! the instant before the `Vec`'s own `Drop` freed them, i.e. exactly
//! whatever `Zeroize::zeroize` did or didn't do to it during
//! `ZeroizeOnDrop`'s `Drop::drop`. This is the "custom test allocator that
//! captures the freed region and asserts it is zeroed" approach.

use luks_core::secret::Secret;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Mutex;

/// The allocation currently being watched, and where its snapshot lands.
static WATCH_PTR: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
static CAPTURED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct CapturingAlloc;

// SAFETY: `alloc`/`dealloc` are pure pass-throughs to `System`, the global
// default allocator; the only addition is a snapshot copy taken from a
// still-valid allocation strictly before it is handed to `System::dealloc`,
// which does not affect the pass-through's own safety obligations.
unsafe impl GlobalAlloc for CapturingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH_PTR.load(Ordering::SeqCst) == ptr {
            let len = WATCH_LEN.load(Ordering::SeqCst);
            // The allocation behind `ptr` is still live and unmodified by
            // this call up to this point — `System::dealloc` has not been
            // invoked yet — so this read is a normal, well-defined read of
            // live memory, not a read of freed memory.
            let snapshot = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            *CAPTURED.lock().unwrap_or_else(|p| p.into_inner()) = snapshot;
            WATCH_PTR.store(std::ptr::null_mut(), Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static ALLOC: CapturingAlloc = CapturingAlloc;

/// Baseline: without dropping anything, a `Secret` exposes exactly the
/// bytes it was constructed with. Pins down that the fixture bytes used
/// below aren't already zero for some unrelated reason, which would make
/// the real test pass vacuously.
#[test]
fn secret_exposes_its_construction_bytes_before_drop() {
    let secret = Secret::new(vec![0xABu8; 64]);
    assert!(secret.expose().iter().all(|&b| b == 0xAB));
}

/// The real proof: the buffer backing a `Secret` is all-zero at the moment
/// it is deallocated, i.e. `ZeroizeOnDrop` ran and did its job before the
/// `Vec` released the memory.
///
/// This is the test N.7 asked for. It is not satisfiable by anything that
/// merely closes a handle — there is no handle here, just a `Vec<u8>`
/// behind `Secret` and its real `Drop` impl, observed through a global
/// allocator hook rather than mocked at any layer.
#[test]
fn zeroize_on_drop_actually_scrubs_the_backing_bytes_before_dealloc() {
    let secret = Secret::new(vec![0xABu8; 64]);

    // Sanity check the fixture is actually non-zero before dropping it, so
    // a pass below can't be hiding an accidentally-already-zero fixture.
    assert!(
        secret.expose().iter().any(|&b| b != 0),
        "fixture must start non-zero or this test proves nothing"
    );

    let ptr = secret.expose().as_ptr() as *mut u8;
    let len = secret.expose().len();

    // Arm the watch just before dropping. `Secret::new` / the assertions
    // above may have performed other allocations (and Rust's test harness
    // itself allocates constantly), but only a `dealloc` whose pointer
    // matches exactly gets captured, so unrelated frees are inert no-ops
    // for this hook.
    WATCH_LEN.store(len, Ordering::SeqCst);
    WATCH_PTR.store(ptr, Ordering::SeqCst);

    drop(secret);

    // If this fires, `Secret`'s allocation was never deallocated during
    // `drop(secret)` at all (e.g. the type stopped owning a `Vec`), which
    // would itself be a break in the property this test exists to check.
    assert_eq!(
        WATCH_PTR.load(Ordering::SeqCst),
        std::ptr::null_mut(),
        "watched allocation was never deallocated — Secret no longer drops its Vec directly?"
    );

    let captured = CAPTURED.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert_eq!(captured.len(), len);
    assert!(
        captured.iter().all(|&b| b == 0),
        "Secret's backing bytes were not zero at the moment of deallocation — \
         ZeroizeOnDrop did not run (or was defeated): {captured:?}"
    );
}
