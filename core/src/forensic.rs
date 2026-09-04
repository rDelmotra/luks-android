//! Forensic in-memory ring buffer for low-level diagnostic tracing.
//!
//! # Security and Privacy Invariants
//!
//! 1. **Zero Filenames & Paths**: Filesystem events store only numeric inode IDs.
//! 2. **Zero File Contents**: Read/write events store only byte lengths, sector counts,
//!    and block/device addresses. File payloads are never buffered.
//! 3. **Zero Key Material**: No passphrases, keyslot metadata, or cipher keys are recorded.
//! 4. **Bounded Capacity**: Fixed circular buffer (256 slots) that drops oldest entries
//!    under load without unbounded memory growth.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const RING_CAPACITY: usize = 256;

static MONOTONIC_SEQ: AtomicU64 = AtomicU64::new(1);

/// An event captured in the forensic ring buffer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", content = "detail")]
pub enum ForensicEvent {
    Usb(UsbEvent),
    Scsi(ScsiEvent),
    Btrfs(BtrfsEvent),
    Panic(PanicEvent),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum UsbEvent {
    Submit { ep: u8, count: usize, bytes: usize, gen: u64 },
    Reap { ep: u8, status: i32, bytes: usize, gen: u64 },
    Timeout { ep: u8, elapsed_ms: u64, active_urbs: usize, gen: u64 },
    StateTransition { from: &'static str, to: &'static str },
    Reset { kind: &'static str, status: i32 },
    Drain { discarded_count: usize, remaining: usize },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ScsiEvent {
    Command { opcode: u8, tag: u32, data_len: u32, dir: &'static str },
    Result { opcode: u8, status: &'static str, transferred: usize, sense_key: Option<u8> },
    Reset,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum BtrfsEvent {
    Mount { generation: u64, root_bytenr: u64 },
    BeginFile { file_len: u64 },
    WriteChunk { len: usize, bytenr: u64 },
    FinishFile { ino: u64, total_bytes: u64 },
    AbandonFile { runs_count: usize, total_bytes: u64 },
    CreateFile { parent_ino: u64, new_ino: u64 },
    DeleteFile { parent_ino: u64, ino: u64 },
    Mkdir { parent_ino: u64, new_ino: u64 },
    Rename { from_parent: u64, to_parent: u64, ino: u64 },
    ChunkAlloc { logical: u64, length: u64, dev_offset: u64 },
    Commit { generation: u64, transid: u64, nodes_written: usize },
    Error { stage: &'static str, code: i32 },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PanicEvent {
    pub file: String,
    pub line: u32,
    pub col: u32,
    pub message: String,
}

/// A timestamped, sequenced record stored in the ring buffer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ForensicRecord {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub event: ForensicEvent,
}

struct RingBuffer {
    entries: [Option<ForensicRecord>; RING_CAPACITY],
    head: usize,
    total_records: u64,
}

impl RingBuffer {
    const fn new() -> Self {
        const NONE_ENTRY: Option<ForensicRecord> = None;
        Self {
            entries: [NONE_ENTRY; RING_CAPACITY],
            head: 0,
            total_records: 0,
        }
    }

    fn push(&mut self, event: ForensicEvent) {
        let seq = MONOTONIC_SEQ.fetch_add(1, Ordering::Relaxed);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record = ForensicRecord {
            seq,
            timestamp_ms,
            event,
        };

        self.entries[self.head] = Some(record);
        self.head = (self.head + 1) % RING_CAPACITY;
        self.total_records = self.total_records.saturating_add(1);
    }

    fn snapshot(&self) -> Vec<ForensicRecord> {
        let mut out = Vec::with_capacity(RING_CAPACITY);
        if self.total_records < RING_CAPACITY as u64 {
            for i in 0..self.head {
                if let Some(ref rec) = self.entries[i] {
                    out.push(rec.clone());
                }
            }
        } else {
            for i in 0..RING_CAPACITY {
                let idx = (self.head + i) % RING_CAPACITY;
                if let Some(ref rec) = self.entries[idx] {
                    out.push(rec.clone());
                }
            }
        }
        out
    }

    fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = None;
        }
        self.head = 0;
        self.total_records = 0;
    }
}

static GLOBAL_RING_BUFFER: Mutex<RingBuffer> = Mutex::new(RingBuffer::new());

/// Record a generic forensic event into the global ring buffer.
pub fn record(event: ForensicEvent) {
    if let Ok(mut buf) = GLOBAL_RING_BUFFER.lock() {
        buf.push(event);
    }
}

/// Helper to record a USB event.
pub fn record_usb(event: UsbEvent) {
    record(ForensicEvent::Usb(event));
}

/// Helper to record a SCSI event.
pub fn record_scsi(event: ScsiEvent) {
    record(ForensicEvent::Scsi(event));
}

/// Helper to record a Btrfs event.
pub fn record_btrfs(event: BtrfsEvent) {
    record(ForensicEvent::Btrfs(event));
}

/// Helper to record a panic event.
pub fn record_panic(file: &str, line: u32, col: u32, message: &str) {
    // Sanitize any potential drive paths in panic messages
    let sanitized_msg = sanitize_message(message);
    let sanitized_file = sanitize_file_path(file);
    record(ForensicEvent::Panic(PanicEvent {
        file: sanitized_file,
        line,
        col,
        message: sanitized_msg,
    }));
}

fn sanitize_file_path(path: &str) -> String {
    // Retain only the filename / relative rust source path
    if let Some(pos) = path.rfind("/src/") {
        path[pos + 1..].to_string()
    } else if let Some(pos) = path.rfind('\\') {
        path[pos + 1..].to_string()
    } else if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        path.to_string()
    }
}

fn sanitize_message(msg: &str) -> String {
    // Strip absolute paths or suspicious segments
    let mut out = String::with_capacity(msg.len());
    let words = msg.split_whitespace();
    for (i, word) in words.enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if word.starts_with('/') || word.starts_with('\\') {
            out.push_str("<redacted_path>");
        } else {
            out.push_str(word);
        }
    }
    out
}

/// Take an in-memory chronological snapshot of the ring buffer records.
pub fn snapshot() -> Vec<ForensicRecord> {
    if let Ok(buf) = GLOBAL_RING_BUFFER.lock() {
        buf.snapshot()
    } else {
        Vec::new()
    }
}

/// Reset the ring buffer (primarily for test isolation).
pub fn clear() {
    if let Ok(mut buf) = GLOBAL_RING_BUFFER.lock() {
        buf.clear();
    }
}

/// Format the ring buffer snapshot as JSON.
pub fn dump_json() -> String {
    let records = snapshot();
    serde_json::to_string_pretty(&records).unwrap_or_else(|_| "[]".to_string())
}

/// Format the ring buffer snapshot as monotonic text lines.
pub fn dump_text() -> String {
    let records = snapshot();
    let mut out = String::new();
    for rec in records {
        out.push_str(&format!("[#{:06} +{}ms] ", rec.seq, rec.timestamp_ms));
        match rec.event {
            ForensicEvent::Usb(ref u) => match u {
                UsbEvent::Submit { ep, count, bytes, gen } => {
                    out.push_str(&format!("USB submit ep={ep} count={count} bytes={bytes} gen={gen}\n"));
                }
                UsbEvent::Reap { ep, status, bytes, gen } => {
                    out.push_str(&format!("USB reap ep={ep} status={status} bytes={bytes} gen={gen}\n"));
                }
                UsbEvent::Timeout { ep, elapsed_ms, active_urbs, gen } => {
                    out.push_str(&format!("USB timeout ep={ep} elapsed={elapsed_ms}ms active={active_urbs} gen={gen}\n"));
                }
                UsbEvent::StateTransition { from, to } => {
                    out.push_str(&format!("USB state: {from} -> {to}\n"));
                }
                UsbEvent::Reset { kind, status } => {
                    out.push_str(&format!("USB reset kind={kind} status={status}\n"));
                }
                UsbEvent::Drain { discarded_count, remaining } => {
                    out.push_str(&format!("USB drain discarded={discarded_count} remaining={remaining}\n"));
                }
            },
            ForensicEvent::Scsi(ref s) => match s {
                ScsiEvent::Command { opcode, tag, data_len, dir } => {
                    out.push_str(&format!("SCSI cmd op=0x{opcode:02X} tag=0x{tag:08X} len={data_len} dir={dir}\n"));
                }
                ScsiEvent::Result { opcode, status, transferred, sense_key } => {
                    out.push_str(&format!(
                        "SCSI res op=0x{opcode:02X} status={status} xfer={transferred} sense={:?}\n",
                        sense_key
                    ));
                }
                ScsiEvent::Reset => {
                    out.push_str("SCSI reset\n");
                }
            },
            ForensicEvent::Btrfs(ref b) => match b {
                BtrfsEvent::Mount { generation, root_bytenr } => {
                    out.push_str(&format!("BTRFS mount gen={generation} root={root_bytenr}\n"));
                }
                BtrfsEvent::BeginFile { file_len } => {
                    out.push_str(&format!("BTRFS begin_file len={file_len}\n"));
                }
                BtrfsEvent::WriteChunk { len, bytenr } => {
                    out.push_str(&format!("BTRFS write_chunk len={len} bytenr={bytenr}\n"));
                }
                BtrfsEvent::FinishFile { ino, total_bytes } => {
                    out.push_str(&format!("BTRFS finish_file ino={ino} bytes={total_bytes}\n"));
                }
                BtrfsEvent::AbandonFile { runs_count, total_bytes } => {
                    out.push_str(&format!("BTRFS abandon_file runs={runs_count} bytes={total_bytes}\n"));
                }
                BtrfsEvent::CreateFile { parent_ino, new_ino } => {
                    out.push_str(&format!("BTRFS create parent_ino={parent_ino} ino={new_ino}\n"));
                }
                BtrfsEvent::DeleteFile { parent_ino, ino } => {
                    out.push_str(&format!("BTRFS delete parent_ino={parent_ino} ino={ino}\n"));
                }
                BtrfsEvent::Mkdir { parent_ino, new_ino } => {
                    out.push_str(&format!("BTRFS mkdir parent_ino={parent_ino} ino={new_ino}\n"));
                }
                BtrfsEvent::Rename { from_parent, to_parent, ino } => {
                    out.push_str(&format!("BTRFS rename from_parent={from_parent} to_parent={to_parent} ino={ino}\n"));
                }
                BtrfsEvent::ChunkAlloc { logical, length, dev_offset } => {
                    out.push_str(&format!("BTRFS chunk_alloc logical={logical} len={length} dev_offset={dev_offset}\n"));
                }
                BtrfsEvent::Commit { generation, transid, nodes_written } => {
                    out.push_str(&format!("BTRFS commit gen={generation} transid={transid} nodes={nodes_written}\n"));
                }
                BtrfsEvent::Error { stage, code } => {
                    out.push_str(&format!("BTRFS error stage={stage} code={code}\n"));
                }
            },
            ForensicEvent::Panic(ref p) => {
                out.push_str(&format!("PANIC at {}:{}:{} - {}\n", p.file, p.line, p.col, p.message));
            }
        }
    }
    out
}
