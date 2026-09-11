use std::sync::Mutex;
use std::thread;

use luks_core::forensic::{
    clear, dump_json, dump_text, record_btrfs, record_panic, record_scsi, record_usb, snapshot,
    BtrfsEvent, ScsiEvent, UsbEvent,
};

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_ring_buffer_bounded_capacity_and_wrap_around() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear();

    // Push 300 events (exceeding RING_CAPACITY of 256)
    for i in 0..300 {
        record_btrfs(BtrfsEvent::WriteChunk {
            len: 4096,
            bytenr: i * 4096,
        });
    }

    let records = snapshot();
    assert_eq!(records.len(), 256, "Ring buffer must hold exactly 256 entries at capacity");

    // Monotonic sequence verification
    for i in 1..records.len() {
        assert!(
            records[i].seq > records[i - 1].seq,
            "Sequences must be strictly monotonically increasing: {} vs {}",
            records[i].seq,
            records[i - 1].seq
        );
    }

    // Verify the oldest retained entry is from the later portion
    if let luks_core::forensic::ForensicEvent::Btrfs(BtrfsEvent::WriteChunk { bytenr, .. }) =
        records[0].event
    {
        assert_eq!(bytenr, 44 * 4096, "Oldest entry should correspond to index 44 (300 - 256)");
    } else {
        panic!("Unexpected event type");
    }

    // Verify the latest entry
    if let luks_core::forensic::ForensicEvent::Btrfs(BtrfsEvent::WriteChunk { bytenr, .. }) =
        records.last().unwrap().event
    {
        assert_eq!(bytenr, 299 * 4096);
    } else {
        panic!("Unexpected event type");
    }
}

#[test]
fn test_privacy_invariants_zero_exposure() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear();

    let sensitive_filename = "my_confidential_passwords.txt";
    let sensitive_content = "super_secret_master_passphrase_12345";

    // Simulate operations using only numeric metadata
    record_btrfs(BtrfsEvent::CreateFile {
        parent_ino: 256,
        new_ino: 257,
    });
    record_btrfs(BtrfsEvent::BeginFile { file_len: 1024 });
    record_btrfs(BtrfsEvent::WriteChunk {
        len: 1024,
        bytenr: 13631488,
    });
    record_btrfs(BtrfsEvent::FinishFile {
        ino: 257,
        total_bytes: 1024,
    });
    record_scsi(ScsiEvent::Command {
        opcode: 0x2A, // WRITE_10
        tag: 0x1234,
        data_len: 1024,
        dir: "OUT",
    });
    record_usb(UsbEvent::Submit {
        ep: 0x02,
        count: 1,
        bytes: 1024,
        gen: 1,
    });

    let text_dump = dump_text();
    let json_dump = dump_json();

    // Verify sensitive data does NOT appear anywhere in text or JSON dumps
    assert!(!text_dump.contains(sensitive_filename));
    assert!(!text_dump.contains(sensitive_content));
    assert!(!json_dump.contains(sensitive_filename));
    assert!(!json_dump.contains(sensitive_content));

    // Verify structural metadata IS present
    assert!(text_dump.contains("BTRFS create parent_ino=256 ino=257"));
    assert!(text_dump.contains("BTRFS begin_file len=1024"));
    assert!(text_dump.contains("BTRFS write_chunk len=1024 bytenr=13631488"));
    assert!(text_dump.contains("BTRFS finish_file ino=257 bytes=1024"));
    assert!(text_dump.contains("SCSI cmd op=0x2A tag=0x00001234 len=1024 dir=OUT"));
    assert!(text_dump.contains("USB submit ep=2 count=1 bytes=1024 gen=1"));
}

#[test]
fn test_concurrent_forensic_logging() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear();

    let threads: Vec<_> = (0..8)
        .map(|t| {
            thread::spawn(move || {
                for i in 0..50 {
                    record_btrfs(BtrfsEvent::WriteChunk {
                        len: 4096,
                        bytenr: (t * 1000 + i) as u64,
                    });
                }
            })
        })
        .collect();

    for handle in threads {
        handle.join().unwrap();
    }

    let records = snapshot();
    assert_eq!(records.len(), 256);

    for i in 1..records.len() {
        assert!(records[i].seq > records[i - 1].seq);
    }
}

#[test]
fn test_panic_trace_sanitization() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear();

    record_panic(
        "/home/developer/workspace/project/core/src/fs/btrfs/mod.rs",
        123,
        45,
        "failed to read /media/usb/private/keyfile.bin: corrupted header",
    );

    let text_dump = dump_text();
    let json_dump = dump_json();

    assert!(text_dump.contains("PANIC at src/fs/btrfs/mod.rs:123:45"));
    assert!(!text_dump.contains("/home/developer"));
    assert!(!text_dump.contains("/media/usb/private/keyfile.bin"));
    assert!(text_dump.contains("<redacted_path>"));

    assert!(json_dump.contains("src/fs/btrfs/mod.rs"));
    assert!(!json_dump.contains("/home/developer"));
}