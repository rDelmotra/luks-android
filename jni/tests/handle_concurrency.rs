//! Concurrent stress tests for the JNI handle registry.
//!
//! Validates that concurrent access (reads/writes) and handle drops (`drop_volume`,
//! `drop_device`, `drop_writer`) are thread-safe and never cause use-after-free,
//! double-free, segfaults, or unhandled panics.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use luks_core::device::{FileDevice, ReadAt};
use luks_jni::bridge::{
    device_ref, drop_device, drop_volume, into_raw, volume_ref, DeviceHandle, Payload,
    VolumeHandle,
};

#[cfg(feature = "dangerous-write-support")]
use luks_jni::bridge::{drop_writer, writer_ref, WriterHandle};

const PASSWORD: &[u8] = b"test";

fn fixture(rel: &str) -> String {
    format!("{}/../fixtures/{rel}", env!("CARGO_MANIFEST_DIR"))
}

fn open_ext4_fixture() -> (DeviceHandle, VolumeHandle) {
    let path = fixture("disks/gpt-luks.img");
    let img = FileDevice::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let blocks = img.len().expect("fixture size") / 512;
    let dev = DeviceHandle::new(img, 512, blocks, "TEST".into(), "IMAGE".into()).expect("scan");
    let offset = dev
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();
    let vol = dev.unlock(offset, PASSWORD).expect("unlock");
    (dev, vol)
}

fn open_btrfs_fixture() -> (DeviceHandle, VolumeHandle) {
    let path = fixture("disks/gpt-luks-btrfs.img");
    let img = FileDevice::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let blocks = img.len().expect("fixture size") / 512;
    let dev = DeviceHandle::new(img, 512, blocks, "TEST".into(), "BTRFS".into()).expect("scan");
    let offset = dev
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();
    let vol = dev.unlock(offset, PASSWORD).expect("unlock");
    (dev, vol)
}

#[test]
fn test_concurrent_readers_and_drop_volume() {
    let (_dev, vol) = open_ext4_fixture();
    let vol_handle = into_raw(Payload::Volume(vol));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let read_success_count = Arc::new(AtomicUsize::new(0));
    let read_closed_count = Arc::new(AtomicUsize::new(0));

    let mut reader_threads = Vec::new();

    for _ in 0..4 {
        let stop = Arc::clone(&stop_signal);
        let success = Arc::clone(&read_success_count);
        let closed = Arc::clone(&read_closed_count);

        reader_threads.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match volume_ref(vol_handle) {
                    Ok(vol) => {
                        let data = vol.read_file("/proof.txt", 1024);
                        assert!(data.is_ok(), "read failed on active handle");
                        assert_eq!(data.unwrap(), b"whole disk stack works\n");

                        let _ = vol.list_dir_json("/");
                        let _ = vol.info_json();
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        assert_eq!(e, "not a luks handle (already closed?)");
                        closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Allow reader threads to perform reads against the valid handle
    thread::sleep(Duration::from_millis(25));

    // Concurrently close the volume handle
    drop_volume(vol_handle);

    // Let reader threads continue hitting the closed handle
    thread::sleep(Duration::from_millis(25));
    stop_signal.store(true, Ordering::Relaxed);

    for t in reader_threads {
        t.join().expect("reader thread panicked");
    }

    assert!(
        read_success_count.load(Ordering::Relaxed) > 0,
        "readers should have succeeded while handle was open"
    );
    assert!(
        read_closed_count.load(Ordering::Relaxed) > 0,
        "readers should have observed handle closure"
    );

    // After all threads joined, subsequent lookups must consistently fail
    assert!(volume_ref(vol_handle).is_err());

    // Double close must be a safe no-op
    drop_volume(vol_handle);
}

#[test]
fn test_concurrent_btrfs_readers_and_drop_volume() {
    let (_dev, vol) = open_btrfs_fixture();
    let vol_handle = into_raw(Payload::Volume(vol));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let read_success_count = Arc::new(AtomicUsize::new(0));
    let read_closed_count = Arc::new(AtomicUsize::new(0));

    let mut reader_threads = Vec::new();

    for _ in 0..4 {
        let stop = Arc::clone(&stop_signal);
        let success = Arc::clone(&read_success_count);
        let closed = Arc::clone(&read_closed_count);

        reader_threads.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match volume_ref(vol_handle) {
                    Ok(vol) => {
                        let data = vol.read_file("/proof.txt", 1024);
                        assert!(data.is_ok());
                        assert_eq!(data.unwrap(), b"whole disk stack works\n");

                        let sub_data = vol.read_file("/sub/nested.txt", 1024);
                        assert!(sub_data.is_ok());
                        assert_eq!(sub_data.unwrap(), b"inside a subvolume\n");

                        let _ = vol.list_dir_json("/");
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        assert_eq!(e, "not a luks handle (already closed?)");
                        closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    thread::sleep(Duration::from_millis(25));
    drop_volume(vol_handle);
    thread::sleep(Duration::from_millis(25));
    stop_signal.store(true, Ordering::Relaxed);

    for t in reader_threads {
        t.join().expect("reader thread panicked");
    }

    assert!(read_success_count.load(Ordering::Relaxed) > 0);
    assert!(read_closed_count.load(Ordering::Relaxed) > 0);
    assert!(volume_ref(vol_handle).is_err());
}

#[test]
fn test_concurrent_device_readers_and_drop_device() {
    let (dev, _vol) = open_ext4_fixture();
    let dev_handle = into_raw(Payload::Device(dev));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let read_success_count = Arc::new(AtomicUsize::new(0));
    let read_closed_count = Arc::new(AtomicUsize::new(0));

    let mut reader_threads = Vec::new();

    for _ in 0..4 {
        let stop = Arc::clone(&stop_signal);
        let success = Arc::clone(&read_success_count);
        let closed = Arc::clone(&read_closed_count);

        reader_threads.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match device_ref(dev_handle) {
                    Ok(dev) => {
                        let info = dev.info_json();
                        assert!(info.contains("GPT"));
                        let bench = dev.benchmark_json(4096, 4096);
                        assert!(bench.is_ok());
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        assert_eq!(e, "not a luks handle (already closed?)");
                        closed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    thread::sleep(Duration::from_millis(25));
    drop_device(dev_handle);
    thread::sleep(Duration::from_millis(25));
    stop_signal.store(true, Ordering::Relaxed);

    for t in reader_threads {
        t.join().expect("reader thread panicked");
    }

    assert!(read_success_count.load(Ordering::Relaxed) > 0);
    assert!(read_closed_count.load(Ordering::Relaxed) > 0);
    assert!(device_ref(dev_handle).is_err());
}

#[test]
fn test_stress_heavy_registry_churn() {
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut handles = Vec::new();

    for _ in 0..8 {
        handles.push(thread::spawn(move || {
            let mut iter = 0;
            while Instant::now() < deadline {
                iter += 1;
                let (dev, vol) = open_ext4_fixture();
                let dev_h = into_raw(Payload::Device(dev));
                let vol_h = into_raw(Payload::Volume(vol));

                assert!(device_ref(dev_h).is_ok());
                assert!(volume_ref(vol_h).is_ok());

                if iter % 2 == 0 {
                    drop_device(dev_h);
                    assert!(device_ref(dev_h).is_err());
                    assert!(volume_ref(vol_h).is_ok()); // volume remains valid
                    drop_volume(vol_h);
                    assert!(volume_ref(vol_h).is_err());
                } else {
                    drop_volume(vol_h);
                    assert!(volume_ref(vol_h).is_err());
                    assert!(device_ref(dev_h).is_ok()); // device remains valid
                    drop_device(dev_h);
                    assert!(device_ref(dev_h).is_err());
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("churn thread panicked");
    }
}

#[cfg(feature = "dangerous-write-support")]
#[test]
fn test_concurrent_writer_and_drop_volume_or_writer() {
    let dst = std::env::temp_dir().join("luks-jni-concurrency-write.img");
    std::fs::copy(fixture("disks/gpt-luks.img"), &dst).expect("copy fixture");
    let len = std::fs::metadata(&dst).expect("stat").len();
    let dev = FileDevice::open_writable(&dst, len).expect("open writable");
    let dev_h =
        DeviceHandle::new(dev, 512, len / 512, "TEST".into(), "WRITE".into()).expect("scan");
    let offset = dev_h
        .table
        .luks_partitions()
        .next()
        .expect("a LUKS partition")
        .offset_bytes();
    let vol = dev_h.unlock(offset, PASSWORD).expect("unlock");

    let vol_h = into_raw(Payload::Volume(vol));
    let vol_ref = volume_ref(vol_h).expect("valid volume handle");
    let writer_enum = vol_ref.begin_file(1024).expect("begin file");

    let writer_h = into_raw(Payload::Writer(WriterHandle {
        volume_handle: vol_h,
        volume_id: vol_ref.id,
        writer: std::sync::Mutex::new(Some(writer_enum)),
    }));

    let stop_signal = Arc::new(AtomicBool::new(false));
    let write_success = Arc::new(AtomicUsize::new(0));
    let write_failed = Arc::new(AtomicUsize::new(0));

    let stop = Arc::clone(&stop_signal);
    let success = Arc::clone(&write_success);
    let failed = Arc::clone(&write_failed);

    let writer_thread = thread::spawn(move || {
        let chunk = vec![0xABu8; 128];
        while !stop.load(Ordering::Relaxed) {
            match (volume_ref(vol_h), writer_ref(writer_h)) {
                (Ok(v), Ok(w)) => {
                    let mut guard = w.writer.lock().unwrap();
                    if let Some(state) = guard.as_mut() {
                        let res = v.write_file_chunk(state, &chunk);
                        if res.is_ok() {
                            success.fetch_add(1, Ordering::Relaxed);
                        } else {
                            failed.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(15));
    drop_writer(writer_h);
    drop_volume(vol_h);
    thread::sleep(Duration::from_millis(15));
    stop_signal.store(true, Ordering::Relaxed);

    writer_thread.join().expect("writer thread panicked");

    assert!(writer_ref(writer_h).is_err());
    assert!(volume_ref(vol_h).is_err());

    let _ = std::fs::remove_file(dst);
}
