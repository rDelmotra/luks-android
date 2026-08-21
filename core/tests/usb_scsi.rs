//! SCSI over Bulk-Only Transport, and partition table parsing.
//!
//! Driven through a USB mass storage emulator (`tests/common`) so everything
//! above the Android usbfs ioctls is covered without hardware.

mod common;

use common::{fixture, MockUsbDrive};
use luks_core::device::ReadAt;
use luks_core::error::LuksError;
use luks_core::partition::{self, type_guid, TableKind};
use luks_core::usb::bot::{
    CommandBlockWrapper, CommandStatusWrapper, CswStatus, Direction, CBW_LEN, CBW_SIGNATURE,
    CSW_LEN, CSW_SIGNATURE,
};
use luks_core::usb::scsi::WriteCacheState;
use luks_core::usb::ScsiBlockDevice;

// --- Bulk-Only Transport wire format ---------------------------------------

#[test]
fn cbw_encodes_to_the_wire_format() {
    let cbw = CommandBlockWrapper::new(0x1234_5678, 512, Direction::In, vec![0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    let b = cbw.encode().unwrap();

    assert_eq!(&b[0..4], b"USBC");
    assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 0x1234_5678);
    assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), 512);
    assert_eq!(b[12], 0x80, "IN direction bit");
    assert_eq!(b[13], 0, "LUN");
    assert_eq!(b[14], 10, "CDB length");
    assert_eq!(b[15], 0x28, "READ(10) opcode");
    assert_eq!(b.len(), 31);
}

#[test]
fn cbw_out_direction_clears_the_flag() {
    let cbw = CommandBlockWrapper::new(1, 0, Direction::Out, vec![0x2A]);
    assert_eq!(cbw.encode().unwrap()[12], 0x00);
}

#[test]
fn cbw_rejects_an_oversized_cdb() {
    let cbw = CommandBlockWrapper::new(1, 0, Direction::In, vec![0u8; 17]);
    assert!(matches!(cbw.encode(), Err(LuksError::ScsiProtocol(_))));
    let cbw = CommandBlockWrapper::new(1, 0, Direction::In, vec![]);
    assert!(matches!(cbw.encode(), Err(LuksError::ScsiProtocol(_))));
}

#[test]
fn csw_decodes_all_statuses() {
    let build = |status: u8| {
        let mut b = [0u8; 13];
        b[0..4].copy_from_slice(b"USBS");
        b[4..8].copy_from_slice(&99u32.to_le_bytes());
        b[8..12].copy_from_slice(&7u32.to_le_bytes());
        b[12] = status;
        b
    };
    let csw = CommandStatusWrapper::decode(&build(0)).unwrap();
    assert_eq!(csw.tag, 99);
    assert_eq!(csw.data_residue, 7);
    assert_eq!(csw.status, CswStatus::Passed);

    assert_eq!(
        CommandStatusWrapper::decode(&build(1)).unwrap().status,
        CswStatus::Failed
    );
    assert_eq!(
        CommandStatusWrapper::decode(&build(2)).unwrap().status,
        CswStatus::PhaseError
    );
    assert!(CommandStatusWrapper::decode(&build(3)).is_err());
}

#[test]
fn csw_rejects_a_bad_signature() {
    let mut b = [0u8; 13];
    b[0..4].copy_from_slice(b"XXXX");
    assert!(matches!(
        CommandStatusWrapper::decode(&b),
        Err(LuksError::ScsiProtocol(_))
    ));
    assert!(CommandStatusWrapper::decode(&[0u8; 5]).is_err());
}

// --- device probing --------------------------------------------------------

#[test]
fn identifies_the_device() {
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let inq = dev.inquiry().unwrap();
    assert_eq!(inq.vendor, "MOCKVEND");
    assert_eq!(inq.product, "MOCK USB DISK");
    assert!(inq.removable);
    assert!(inq.is_block_device());
}

#[test]
fn reads_capacity() {
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let dev = ScsiBlockDevice::open(drive).unwrap();
    let cap = dev.capacity();
    assert_eq!(cap.block_size, 512);
    assert_eq!(cap.bytes(), 24 * 1024 * 1024);
    assert_eq!(cap.blocks, 24 * 1024 * 1024 / 512);
}

/// Drives at or above 2 TiB report 0xFFFFFFFF from READ CAPACITY(10) and must
/// be re-queried with the 16-byte form.
#[test]
fn falls_back_to_read_capacity_16() {
    let mut drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    drive.force_rc16 = true;
    let dev = ScsiBlockDevice::open(drive).unwrap();
    assert_eq!(dev.capacity().bytes(), 24 * 1024 * 1024);
}

// --- byte-addressed reads over block-addressed SCSI ------------------------

#[test]
fn reads_match_the_underlying_image() {
    let image = fixture("disks/gpt-luks.img");
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(image.clone())).unwrap();

    for (offset, len) in [
        (0u64, 512usize),
        (0, 1),
        (1, 1),
        (511, 2),      // straddles a block
        (513, 1000),   // unaligned start and end
        (4096, 65536), // spans many blocks
        (1_000_000, 4096),
        (24 * 1024 * 1024 - 10, 10), // last bytes
    ] {
        let mut got = vec![0u8; len];
        dev.read_at(offset, &mut got)
            .unwrap_or_else(|e| panic!("read at {offset} len {len}: {e}"));
        assert_eq!(
            got,
            &image[offset as usize..offset as usize + len],
            "mismatch at offset={offset} len={len}"
        );
    }
}

#[test]
fn rejects_reads_past_the_end() {
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(fixture("disks/gpt-luks.img"))).unwrap();
    let mut buf = [0u8; 16];
    assert!(matches!(
        dev.read_at(24 * 1024 * 1024, &mut buf),
        Err(LuksError::OutOfBounds)
    ));
    assert!(matches!(
        dev.read_at(24 * 1024 * 1024 - 8, &mut buf),
        Err(LuksError::OutOfBounds)
    ));
}

/// A naive implementation issues one command per block. Reads must be batched
/// up to the transport's limit, since BOT serialises command round-trips and
/// that is what bounds throughput.
#[test]
fn large_reads_are_batched_into_few_commands() {
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).with_max_transfer(128 * 1024);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let mut buf = vec![0u8; 1024 * 1024];
    dev.read_at(0, &mut buf).unwrap();

    let stats = *dev.transport().stats.borrow();
    // 1 MiB in 128 KiB commands = 8. Allow a little slack for alignment.
    assert!(
        stats.read_commands <= 10,
        "expected batched reads, got {} commands",
        stats.read_commands
    );
    assert_eq!(stats.largest_read_blocks, 256, "128 KiB / 512-byte blocks");
}

/// A transport with a small per-URB cap must still produce correct data.
#[test]
fn respects_a_small_transfer_limit() {
    let image = fixture("disks/gpt-luks.img");
    let drive = MockUsbDrive::new(image.clone()).with_max_transfer(16 * 1024);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let mut buf = vec![0u8; 256 * 1024];
    dev.read_at(8192, &mut buf).unwrap();
    assert_eq!(buf, &image[8192..8192 + 256 * 1024]);

    assert_eq!(dev.transport().stats.borrow().largest_read_blocks, 32);
}

#[test]
fn works_with_4096_byte_blocks() {
    let image = fixture("disks/gpt-luks.img");
    let drive = MockUsbDrive::new(image.clone()).with_block_size(4096);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    assert_eq!(dev.capacity().block_size, 4096);
    let mut buf = vec![0u8; 10000];
    dev.read_at(5000, &mut buf).unwrap();
    assert_eq!(buf, &image[5000..15000]);
}

// --- partition tables ------------------------------------------------------

#[test]
fn parses_the_gpt_and_finds_the_luks_partition() {
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(fixture("disks/gpt-luks.img"))).unwrap();
    let table = partition::scan(&dev, dev.capacity().block_size).unwrap();

    assert_eq!(table.kind, TableKind::Gpt);
    assert_eq!(table.partitions.len(), 2);

    // Ground truth from `sgdisk -p`, recorded in fixtures/disks/GPT-LAYOUT.txt.
    let p1 = &table.partitions[0];
    assert_eq!(p1.index, 1);
    assert_eq!(p1.name, "plainpart");
    assert_eq!(p1.start_lba, 2048);
    assert_eq!(p1.end_lba, 6143);
    assert_eq!(p1.size_bytes(), 2 * 1024 * 1024);
    assert!(!p1.is_luks);

    let p2 = &table.partitions[1];
    assert_eq!(p2.index, 2);
    assert_eq!(p2.name, "cryptdata");
    assert_eq!(p2.start_lba, 6144);
    assert_eq!(p2.offset_bytes(), 6144 * 512);
    assert!(p2.is_luks, "LUKS partition not detected");
    assert_eq!(p2.luks_version, Some(2));
    assert_eq!(p2.type_guid, Some(type_guid::LUKS));
    assert_eq!(
        p2.type_guid_string().unwrap(),
        "CA7D7CCB-63ED-4C53-861C-1742536059CC"
    );

    assert_eq!(table.luks_partitions().count(), 1);
}

#[test]
fn parses_an_mbr_disk() {
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(fixture("disks/mbr-luks.img"))).unwrap();
    let table = partition::scan(&dev, dev.capacity().block_size).unwrap();

    assert_eq!(table.kind, TableKind::Mbr);
    assert_eq!(table.partitions.len(), 1);

    let p = &table.partitions[0];
    assert_eq!(p.start_lba, 2048);
    assert_eq!(p.mbr_type, Some(0x83));
    assert!(p.type_guid.is_none());
    assert!(p.is_luks, "LUKS not detected on MBR disk");
    assert_eq!(p.luks_version, Some(2));
}

/// A damaged primary GPT must fall back to the backup at the end of the disk,
/// the same way the LUKS header recovers from its secondary copy.
#[test]
fn recovers_from_a_damaged_primary_gpt() {
    let mut image = fixture("disks/gpt-luks.img");
    // Corrupt the primary header at LBA 1 — the CRC check will reject it.
    image[512 + 40] ^= 0xFF;

    let dev = ScsiBlockDevice::open(MockUsbDrive::new(image)).unwrap();
    let table = partition::scan(&dev, 512).unwrap();

    assert_eq!(table.kind, TableKind::Gpt);
    assert_eq!(table.partitions.len(), 2);
    assert!(table.partitions[1].is_luks);
}

#[test]
fn reports_no_table_on_blank_media() {
    let dev = ScsiBlockDevice::open(MockUsbDrive::new(vec![0u8; 1024 * 1024])).unwrap();
    assert!(partition::scan(&dev, 512).is_err());
}

// --- BOT error recovery (#14) -----------------------------------------------

/// Wraps a real transport and can be armed to fail one specific call by
/// number, while counting how many times `reset()` fires. Everything else
/// delegates straight through, so `ScsiBlockDevice::open` — which itself
/// issues several commands — behaves normally until `arm` is called.
struct FlakyTransport<T> {
    inner: T,
    fail_on_call: std::cell::Cell<Option<usize>>,
    call_count: std::cell::Cell<usize>,
    reset_count: std::cell::Cell<usize>,
}

impl<T> FlakyTransport<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            fail_on_call: std::cell::Cell::new(None),
            call_count: std::cell::Cell::new(0),
            reset_count: std::cell::Cell::new(0),
        }
    }

    /// Fail the `on_call`-th `write`/`read` from this point on (1-indexed),
    /// resetting the counter so the next command starts counting at 1.
    fn arm(&self, on_call: usize) {
        self.call_count.set(0);
        self.fail_on_call.set(Some(on_call));
    }

    fn should_fail(&self) -> bool {
        let n = self.call_count.get() + 1;
        self.call_count.set(n);
        Some(n) == self.fail_on_call.get()
    }
}

impl<T: luks_core::usb::BulkTransport> luks_core::usb::BulkTransport for FlakyTransport<T> {
    fn write(&self, data: &[u8]) -> Result<usize, LuksError> {
        if self.should_fail() {
            return Err(LuksError::UsbTransfer("injected failure".into()));
        }
        self.inner.write(data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, LuksError> {
        if self.should_fail() {
            return Err(LuksError::UsbTransfer("injected failure".into()));
        }
        self.inner.read(buf)
    }

    fn max_transfer(&self) -> usize {
        self.inner.max_transfer()
    }

    fn clear_halt(&self, endpoint_in: bool) -> Result<(), LuksError> {
        self.inner.clear_halt(endpoint_in)
    }

    fn reset(&self) -> Result<(), LuksError> {
        self.reset_count.set(self.reset_count.get() + 1);
        self.inner.reset()
    }
}

/// The regression #14 exists for: before this fix, a transport-level
/// failure (a real bulk timeout, not a CSW-reported command failure)
/// propagated straight up with no attempt to reset the bus, leaving a real
/// bridge wedged until a physical replug. `arm(1)` fails the very first
/// transport call of the next command — the CBW write — which is as close
/// as this mock gets to "the drive stopped answering".
#[test]
fn a_transport_failure_triggers_a_bot_reset_before_propagating() {
    let dev = ScsiBlockDevice::open(FlakyTransport::new(MockUsbDrive::new(vec![0u8; 1024 * 1024])))
        .unwrap();

    dev.transport().arm(1);
    let mut buf = [0u8; 512];
    let err = dev.read_at(0, &mut buf).unwrap_err();

    assert!(
        matches!(err, LuksError::UsbTransfer(_)),
        "the injected failure must still be what the caller sees: {err}"
    );
    assert_eq!(
        dev.transport().reset_count.get(),
        1,
        "a transport-level failure must trigger exactly one BOT reset"
    );
}

/// The control for the test above: with the transport never armed, a normal
/// read must not touch reset at all. Without this, a version of the fix that
/// resets unconditionally on every command would pass the test above for
/// the wrong reason.
#[test]
fn a_clean_transfer_never_touches_reset() {
    let dev = ScsiBlockDevice::open(FlakyTransport::new(MockUsbDrive::new(vec![0u8; 1024 * 1024])))
        .unwrap();

    let mut buf = [0u8; 512];
    dev.read_at(0, &mut buf).unwrap();

    assert_eq!(dev.transport().reset_count.get(), 0);
}

#[test]
fn guid_formatting_uses_mixed_endian_order() {
    // GPT stores the first three fields little-endian; printing must undo that.
    assert_eq!(
        partition::format_guid(&type_guid::EFI_SYSTEM),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    );
    assert_eq!(
        partition::format_guid(&type_guid::LINUX_FS),
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    );
}

struct CswStallTransport<T> {
    inner: T,
    stall_csw: std::cell::Cell<bool>,
    clear_halt_called: std::cell::Cell<bool>,
    reset_called: std::cell::Cell<bool>,
}

impl<T> CswStallTransport<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            stall_csw: std::cell::Cell::new(false),
            clear_halt_called: std::cell::Cell::new(false),
            reset_called: std::cell::Cell::new(false),
        }
    }
}

impl<T: luks_core::usb::BulkTransport> luks_core::usb::BulkTransport for CswStallTransport<T> {
    fn write(&self, data: &[u8]) -> Result<usize, LuksError> {
        self.inner.write(data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, LuksError> {
        if self.stall_csw.get() && buf.len() == 13 && !self.clear_halt_called.get() {
            return Err(LuksError::UsbTransfer(
                "USBDEVFS_BULK: errno 32 (Broken pipe) (endpoint stalled)".into(),
            ));
        }
        self.inner.read(buf)
    }

    fn max_transfer(&self) -> usize {
        self.inner.max_transfer()
    }

    fn clear_halt(&self, endpoint_in: bool) -> Result<(), LuksError> {
        if endpoint_in {
            self.clear_halt_called.set(true);
        }
        self.inner.clear_halt(endpoint_in)
    }

    fn reset(&self) -> Result<(), LuksError> {
        self.reset_called.set(true);
        self.inner.reset()
    }
}

#[test]
fn csw_stall_recovers_via_clear_halt() {
    let raw_drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let transport = CswStallTransport::new(raw_drive);
    let dev = ScsiBlockDevice::open(transport).unwrap();

    dev.transport().stall_csw.set(true);
    dev.transport().clear_halt_called.set(false);
    dev.transport().reset_called.set(false);

    let inq = dev.inquiry().expect("inquiry should recover from CSW stall via clear_halt");
    assert!(inq.is_block_device());
    assert!(dev.transport().clear_halt_called.get(), "clear_halt(true) must be called");
    assert!(!dev.transport().reset_called.get(), "reset() must not be called when clear_halt succeeds");
}

#[test]
fn max_scsi_transfer_caps_single_read_commands() {
    // A transport that allows 1 MiB transfers
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img")).with_max_transfer(1024 * 1024);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    let mut buf = vec![0u8; 1024 * 1024];
    dev.read_at(0, &mut buf).unwrap();

    let stats = *dev.transport().stats.borrow();
    // 1 MiB in 128 KiB commands = 8 commands
    assert!(stats.read_commands >= 8, "must split into at least 8 commands");
    assert_eq!(stats.largest_read_blocks, 256, "capped at 128 KiB / 512 = 256 blocks");
}

// --- MODE SENSE / write-cache probe -----------------------------------------
//
// `MockUsbDrive` (in `tests/common`) has no notion of the Caching mode page —
// its command dispatch falls through to a generic "command failed" for any
// opcode it does not recognise, MODE SENSE(6)/(10) included. Rather than
// extend that shared fixture (owned by other work in this crate), the tests
// below wrap a working `MockUsbDrive` in a small transport that intercepts
// only MODE SENSE(6)/(10) and answers with a caller-supplied body, passing
// every other opcode straight through so `ScsiBlockDevice::open` still
// succeeds normally. This follows the same pattern as `FlakyTransport` and
// `CswStallTransport` above: wrap `BulkTransport`, delegate by default,
// intercept the one thing under test.

enum ModeSensePhase {
    /// Not intercepting: reads are the inner transport's business.
    Idle,
    /// Serving `response` bytes for the data-in phase of an intercepted
    /// MODE SENSE.
    DataIn { pos: usize },
    /// Serving the CSW that follows an intercepted MODE SENSE.
    Csw { pos: usize },
}

/// Wraps a working drive and substitutes a fixed MODE SENSE(6)/(10) response
/// for opcodes 0x1A and 0x5A. Everything else — INQUIRY, TEST UNIT READY,
/// READ CAPACITY, and so on — passes straight through to `inner`.
struct ModeSenseTransport<T> {
    inner: T,
    /// The bytes to serve after a MODE SENSE CBW, however short: a genuinely
    /// truncated response is one of the cases under test, and the reader must
    /// see exactly what was handed to it, not padding invented here.
    response: Vec<u8>,
    phase: std::cell::RefCell<ModeSensePhase>,
    csw: std::cell::Cell<[u8; CSW_LEN]>,
}

impl<T> ModeSenseTransport<T> {
    fn new(inner: T, response: Vec<u8>) -> Self {
        Self {
            inner,
            response,
            phase: std::cell::RefCell::new(ModeSensePhase::Idle),
            csw: std::cell::Cell::new([0u8; CSW_LEN]),
        }
    }
}

impl<T: luks_core::usb::BulkTransport> luks_core::usb::BulkTransport for ModeSenseTransport<T> {
    fn write(&self, data: &[u8]) -> Result<usize, LuksError> {
        // A CBW is always encoded to exactly CBW_LEN bytes and sent in one
        // `write` call (see `ScsiBlockDevice::command_inner`), so a CBW-sized
        // write starting with the signature is unambiguously a fresh command,
        // never mid-phase payload — MODE SENSE has no OUT data of its own.
        if data.len() == CBW_LEN
            && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == CBW_SIGNATURE
        {
            let tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let opcode = data[15];
            if opcode == 0x1A || opcode == 0x5A {
                let mut csw = [0u8; CSW_LEN];
                csw[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
                csw[4..8].copy_from_slice(&tag.to_le_bytes());
                // Residue is unchecked for an IN transfer (see the comment in
                // `command_inner`), so leaving it at 0 is fine even when the
                // response is shorter than the host asked for.
                csw[12] = 0; // GOOD
                self.csw.set(csw);
                *self.phase.borrow_mut() = ModeSensePhase::DataIn { pos: 0 };
                return Ok(CBW_LEN);
            }
        }
        self.inner.write(data)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, LuksError> {
        let mut phase = self.phase.borrow_mut();
        match &mut *phase {
            ModeSensePhase::Idle => {
                drop(phase);
                self.inner.read(buf)
            }
            ModeSensePhase::DataIn { pos } => {
                let n = (self.response.len() - *pos).min(buf.len());
                if n == 0 {
                    // The device has nothing left to send. A real short
                    // packet ends the IN phase here; the next `read` call is
                    // for the CSW, not more of this response.
                    *phase = ModeSensePhase::Csw { pos: 0 };
                    return Ok(0);
                }
                buf[..n].copy_from_slice(&self.response[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            }
            ModeSensePhase::Csw { pos } => {
                let csw = self.csw.get();
                let n = (CSW_LEN - *pos).min(buf.len());
                buf[..n].copy_from_slice(&csw[*pos..*pos + n]);
                *pos += n;
                if *pos == CSW_LEN {
                    *phase = ModeSensePhase::Idle;
                }
                Ok(n)
            }
        }
    }

    fn max_transfer(&self) -> usize {
        self.inner.max_transfer()
    }

    fn clear_halt(&self, endpoint_in: bool) -> Result<(), LuksError> {
        self.inner.clear_halt(endpoint_in)
    }

    fn reset(&self) -> Result<(), LuksError> {
        self.inner.reset()
    }
}

/// Build a MODE SENSE(6) response: 4-byte header (with the given block
/// descriptor length), that many bytes of block descriptor, then a Caching
/// mode page carrying `wce` in bit 2 of byte 2.
///
/// The block descriptor bytes are filled with `0xEE` — a pattern that looks
/// nothing like a valid Caching page (page code 0x08) — specifically so a
/// parser that forgets to skip the descriptor and reads the page from a fixed
/// offset instead would trip over it rather than accidentally agreeing.
fn mode_sense_6_response(block_descriptor_len: u8, wce: bool) -> Vec<u8> {
    let mut d = vec![0u8; 4 + block_descriptor_len as usize + 20];
    d[3] = block_descriptor_len;
    for b in &mut d[4..4 + block_descriptor_len as usize] {
        *b = 0xEE;
    }
    let page = &mut d[4 + block_descriptor_len as usize..];
    page[0] = 0x08; // page code, PS bit clear
    page[1] = 18; // page length (bytes following this one)
    page[2] = if wce { 0x04 } else { 0x00 };
    d[0] = (d.len() - 1) as u8; // mode data length
    d
}

#[test]
fn write_cache_state_reports_enabled_when_wce_bit_is_set() {
    let inner = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let transport = ModeSenseTransport::new(inner, mode_sense_6_response(0, true));
    let dev = ScsiBlockDevice::open(transport).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Enabled);
}

#[test]
fn write_cache_state_reports_disabled_when_wce_bit_is_clear() {
    let inner = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let transport = ModeSenseTransport::new(inner, mode_sense_6_response(0, false));
    let dev = ScsiBlockDevice::open(transport).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Disabled);
}

/// The descriptor-skip regression: an 8-byte block descriptor sits between
/// the header and the Caching page, filled with bytes (0xEE) that are not a
/// valid page code. A parser that reads the page from a fixed offset — i.e.
/// forgets to skip the descriptor, or skips the wrong number of bytes — reads
/// the WCE bit from `0xEE` territory instead, which this test was run
/// against once (see the report) and observed to fail before the offset was
/// corrected.
#[test]
fn write_cache_state_skips_a_nonzero_block_descriptor() {
    let inner = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let transport = ModeSenseTransport::new(inner, mode_sense_6_response(8, true));
    let dev = ScsiBlockDevice::open(transport).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Enabled);

    let inner2 = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    let transport2 = ModeSenseTransport::new(inner2, mode_sense_6_response(8, false));
    let dev2 = ScsiBlockDevice::open(transport2).unwrap();

    assert_eq!(dev2.write_cache_state(), WriteCacheState::Disabled);
}

/// Both MODE SENSE forms rejected as an invalid opcode: MODE SENSE(6) is
/// probed first, then the drive is also made to reject MODE SENSE(10), so the
/// fallback is exhausted rather than incidentally succeeding.
#[test]
fn write_cache_state_is_unknown_when_mode_sense_is_rejected() {
    let drive = MockUsbDrive::new(fixture("disks/gpt-luks.img"))
        .failing(0x1A, [0x05, 0x20, 0x00])
        .failing(0x5A, [0x05, 0x20, 0x00]);
    let dev = ScsiBlockDevice::open(drive).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Unknown);
}

/// A response too short to contain a Caching page at all — just the 4-byte
/// header, no block descriptor and nothing after it — must not be read past
/// its end, and must not be mistaken for an answer.
#[test]
fn write_cache_state_is_unknown_on_a_truncated_response() {
    let inner = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    // Header only: mode data length, medium type, device-specific parameter,
    // block descriptor length (0). No page follows.
    let transport = ModeSenseTransport::new(inner, vec![3, 0, 0, 0]);
    let dev = ScsiBlockDevice::open(transport).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Unknown);
}

/// A response that claims a block descriptor longer than what was actually
/// returned must not be trusted either — walking off the end of `data` here
/// would be the same class of bug as the descriptor-skip test above, just in
/// the direction of reading too far rather than not far enough.
#[test]
fn write_cache_state_is_unknown_when_the_descriptor_overruns_the_response() {
    let inner = MockUsbDrive::new(fixture("disks/gpt-luks.img"));
    // Header says a 200-byte block descriptor follows; only 4 bytes of body
    // exist after the header.
    let transport = ModeSenseTransport::new(inner, vec![7, 0, 0, 200, 0xEE, 0xEE, 0xEE, 0xEE]);
    let dev = ScsiBlockDevice::open(transport).unwrap();

    assert_eq!(dev.write_cache_state(), WriteCacheState::Unknown);
}
