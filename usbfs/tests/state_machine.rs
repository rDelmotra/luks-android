use std::collections::VecDeque;
use std::os::raw::{c_int, c_void};
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use luks_core::error::LuksError;
use luks_core::usb::BulkTransport;
use luks_usbfs::*;

#[derive(Default)]
struct MockState {
    submitted_urbs: Vec<(u8, usize)>, // (endpoint, buffer_length)
    discarded_count: usize,
    poll_events: VecDeque<std::result::Result<libc::c_short, i32>>,
    reap_events: VecDeque<(c_int, usize)>, // (rc, usercontext_token)
    default_poll_err: Option<i32>,
}

struct MockRawUsbFs {
    state: Mutex<MockState>,
}

impl MockRawUsbFs {
    fn new() -> Self {
        Self {
            state: Mutex::new(MockState::default()),
        }
    }

    fn push_poll(&self, res: std::result::Result<libc::c_short, i32>) {
        self.state.lock().unwrap().poll_events.push_back(res);
    }

    fn push_reap(&self, rc: c_int, token: usize) {
        self.state.lock().unwrap().reap_events.push_back((rc, token));
    }

    fn set_default_poll_err(&self, err: i32) {
        self.state.lock().unwrap().default_poll_err = Some(err);
    }

    fn submitted_count(&self) -> usize {
        self.state.lock().unwrap().submitted_urbs.len()
    }

    fn discarded_count(&self) -> usize {
        self.state.lock().unwrap().discarded_count
    }
}

impl RawUsbFs for MockRawUsbFs {
    fn ioctl(&self, _fd: RawFd, req: u64, arg: *mut c_void) -> c_int {
        let req_submit = submit_urb_code() as u64;
        let req_discard = discard_urb_code() as u64;
        let req_reap = reap_urb_code() as u64;

        if req == req_submit {
            let urb = unsafe { &mut *(arg as *mut UsbdevfsUrb) };
            self.state.lock().unwrap().submitted_urbs.push((urb.endpoint, urb.buffer_length as usize));
            0
        } else if req == req_discard {
            self.state.lock().unwrap().discarded_count += 1;
            0
        } else if req == req_reap {
            let mut state = self.state.lock().unwrap();
            if let Some((rc, token)) = state.reap_events.pop_front() {
                if rc >= 0 {
                    let reaped_ptr = arg as *mut *mut c_void;
                    unsafe {
                        *reaped_ptr = token as *mut c_void;
                    }
                }
                rc
            } else {
                -1
            }
        } else {
            0
        }
    }

    fn poll(&self, _fd: RawFd, _events: libc::c_short, _timeout_ms: i32) -> std::result::Result<libc::c_short, i32> {
        let mut state = self.state.lock().unwrap();
        if let Some(res) = state.poll_events.pop_front() {
            return res;
        }
        if let Some(err) = state.default_poll_err {
            return Err(err);
        }
        Ok(libc::POLLOUT)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn normal_transfer_submits_and_reaps_cleanly() {
    let mock = Arc::new(MockRawUsbFs::new());
    // 64 KiB buffer -> 1 chunk -> slot 0 (token = 1)
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1);

    let transport = unsafe { UsbFsTransport::from_raw_fd(10, 0x81, 0x02, 0) }
        .with_raw_usbfs(mock.clone())
        .with_timeout_ms(100);

    let data = vec![0x42u8; 64 * 1024];
    let _written = transport.write(&data).expect("write");
    assert_eq!(mock.submitted_count(), 1);
    assert_eq!(mock.discarded_count(), 0);
    assert_eq!(transport.state(), TransportState::Healthy);
}

#[test]
fn timeout_on_reap_drains_discarded_urbs_and_recovers_to_healthy() {
    let mock = Arc::new(MockRawUsbFs::new());

    // 1st poll times out
    mock.push_poll(Err(libc::ETIMEDOUT));
    // 2nd poll (during drain) succeeds and reaps slot 0 with token = 1
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1);

    let transport = unsafe { UsbFsTransport::from_raw_fd(10, 0x81, 0x02, 0) }
        .with_raw_usbfs(mock.clone())
        .with_timeout_ms(50);

    let data = vec![0x42u8; 64 * 1024];
    let err = transport.write(&data).unwrap_err();
    assert!(
        matches!(err, LuksError::UsbTransfer(ref m) if m.contains("timed out")),
        "expected timed out error, got: {err}"
    );

    // Assert DISCARDURB was issued
    assert_eq!(mock.discarded_count(), 1);
    // Assert all URBs were drained, so state recovered to Healthy!
    assert_eq!(transport.state(), TransportState::Healthy);

    // A subsequent transfer can proceed normally
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1);
    let _ = transport.write(&data);
    assert_eq!(transport.state(), TransportState::Healthy);
}

#[test]
fn timeout_with_unreaped_urbs_latches_to_dead_and_fast_refuses() {
    let mock = Arc::new(MockRawUsbFs::new());

    // Poll always times out (kernel never answers)
    mock.set_default_poll_err(libc::ETIMEDOUT);

    let transport = unsafe { UsbFsTransport::from_raw_fd(10, 0x81, 0x02, 0) }
        .with_raw_usbfs(mock.clone())
        .with_timeout_ms(20); // short timeout so test runs fast

    let data = vec![0x42u8; 64 * 1024];
    let err = transport.write(&data).unwrap_err();
    assert!(
        matches!(err, LuksError::UsbTransfer(ref m) if m.contains("timed out") || m.contains("dead")),
        "expected timeout/dead error, got: {err}"
    );

    // Because drain deadline expired without reaping, state MUST be Dead
    assert_eq!(transport.state(), TransportState::Dead);

    // Subsequent operations MUST fast-refuse immediately without issuing ioctls
    let prev_submitted = mock.submitted_count();
    let second_err = transport.write(&data).unwrap_err();
    assert!(
        matches!(second_err, LuksError::UsbTransfer(ref m) if m.contains("dead")),
        "expected dead refusal, got: {second_err}"
    );
    assert_eq!(mock.submitted_count(), prev_submitted, "no new submissions when Dead");

    let mut read_buf = [0u8; 64];
    let read_err = transport.read(&mut read_buf).unwrap_err();
    assert!(matches!(read_err, LuksError::UsbTransfer(ref m) if m.contains("dead")));

    let clear_err = transport.clear_halt(true).unwrap_err();
    assert!(matches!(clear_err, LuksError::UsbTransfer(ref m) if m.contains("dead")));

    let reset_err = transport.reset().unwrap_err();
    assert!(matches!(reset_err, LuksError::UsbTransfer(ref m) if m.contains("dead")));
}

#[test]
fn delayed_stale_completion_from_earlier_generation_does_not_corrupt_or_panic() {
    let mock = Arc::new(MockRawUsbFs::new());

    // Transfer 1: 1 chunk -> slot 0 (token = 1). Times out, drained with token = 1.
    mock.push_poll(Err(libc::ETIMEDOUT));
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1); // reaps slot 0 (generation 1)

    let transport = unsafe { UsbFsTransport::from_raw_fd(10, 0x81, 0x02, 0) }
        .with_raw_usbfs(mock.clone())
        .with_timeout_ms(50);

    let data = vec![0x42u8; 64 * 1024];
    let _ = transport.write(&data);
    assert_eq!(transport.state(), TransportState::Healthy);

    // Transfer 2: Starts with generation 2, uses slot 0 (token = 1).
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1);

    let _ = transport.write(&data);
    assert_eq!(transport.state(), TransportState::Healthy);
}

#[test]
fn invalid_or_corrupt_usercontext_from_kernel_is_safely_ignored() {
    let mock = Arc::new(MockRawUsbFs::new());

    // Kernel returns garbage usercontext pointers (0xDEADBEEF, 0x0) before the real token (1)
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 0xDEADBEEF);
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 0);
    mock.push_poll(Ok(libc::POLLOUT));
    mock.push_reap(0, 1); // valid token

    let transport = unsafe { UsbFsTransport::from_raw_fd(10, 0x81, 0x02, 0) }
        .with_raw_usbfs(mock.clone())
        .with_timeout_ms(50);

    let data = vec![0x42u8; 64 * 1024];
    let _ = transport.write(&data);
    assert_eq!(transport.state(), TransportState::Healthy);
}
