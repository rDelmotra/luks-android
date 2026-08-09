//! JNI entry points for `dev.luksandroid.LuksNative`.
//!
//! This file does marshalling and nothing else: Java values in, Rust values out,
//! and the reverse. All behaviour lives in [`bridge`], which has no JNI types in
//! it and is tested on the host.
//!
//! Two rules hold for every function here, and both have teeth:
//!
//! 1. **Wrapped in `catch_unwind`.** We parse GPT, LUKS and ext4 metadata that
//!    an attacker or a failing drive controls. A panic crossing the JNI boundary
//!    is undefined behaviour and shows up as a process abort with no Java stack
//!    trace. Caught, it becomes a `LuksException` the app can display. This is
//!    also why the release profile does not set `panic = "abort"`.
//! 2. **Passwords arrive as `byte[]`, never `String`.** A Java `String` is
//!    immutable and lives on the GC heap until collected, so it cannot be
//!    scrubbed. The array is copied into a [`Secret`](luks_core::secret::Secret)
//!    here and zeroed on drop; Kotlin overwrites its own copy in a `finally`.

pub mod bridge;

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JString, JValue};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

use luks_core::error::LuksError;

const EXCEPTION_CLASS: &str = "dev/luksandroid/LuksException";

/// What a failed entry point reports back to Java.
enum Fail {
    Luks(LuksError),
    Msg(i32, String),
}

impl From<LuksError> for Fail {
    fn from(e: LuksError) -> Self {
        Fail::Luks(e)
    }
}

impl Fail {
    fn parts(&self) -> (i32, String) {
        match self {
            Fail::Luks(e) => (bridge::error_code(e), e.to_string()),
            Fail::Msg(c, m) => (*c, m.clone()),
        }
    }
}

type R<T> = std::result::Result<T, Fail>;

/// Run `f`, turning any error *or panic* into a thrown `LuksException` and
/// returning `default`.
///
/// `AssertUnwindSafe` is honest here rather than a papering-over: on the panic
/// path we touch none of the state the closure was mutating. We read the panic
/// payload, throw, and return a default value the caller discards because an
/// exception is pending.
fn guard<'l, T>(env: &mut JNIEnv<'l>, default: T, f: impl FnOnce(&mut JNIEnv<'l>) -> R<T>) -> T {
    let outcome = catch_unwind(AssertUnwindSafe(|| f(env)));
    match outcome {
        Ok(Ok(value)) => value,
        Ok(Err(fail)) => {
            let (code, msg) = fail.parts();
            throw(env, code, &msg);
            default
        }
        Err(payload) => {
            let msg = panic_message(&payload);
            throw(
                env,
                bridge::code::PANIC,
                &format!("internal error (this is a bug): {msg}"),
            );
            default
        }
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic with a non-string payload".to_string()
    }
}

/// Throw `LuksException(message, code)`.
///
/// Falls back to `RuntimeException` if our own class is missing, which happens
/// if the `.so` and the APK drift apart. Silently swallowing that would produce
/// a call that neither returns a value nor throws — the worst possible outcome.
fn throw(env: &mut JNIEnv, code: i32, message: &str) {
    if env.exception_check().unwrap_or(false) {
        return; // something already threw; do not mask it
    }
    let attempt = (|| -> jni::errors::Result<()> {
        let class = env.find_class(EXCEPTION_CLASS)?;
        let jmsg = env.new_string(message)?;
        let ex = env.new_object(
            class,
            "(Ljava/lang/String;I)V",
            &[JValue::Object(&jmsg), JValue::Int(code)],
        )?;
        env.throw(jni::objects::JThrowable::from(ex))?;
        Ok(())
    })();

    if attempt.is_err() {
        let _ = env.exception_clear();
        let _ = env.throw_new("java/lang/RuntimeException", message);
    }
}

fn jstr(env: &mut JNIEnv, s: &JString) -> R<String> {
    env.get_string(s)
        .map(|v| v.into())
        .map_err(|e| Fail::Msg(bridge::code::GENERIC, format!("bad string argument: {e}")))
}

fn out_string(env: &mut JNIEnv, s: &str) -> R<jstring> {
    env.new_string(s).map(|v| v.into_raw()).map_err(|e| {
        Fail::Msg(
            bridge::code::GENERIC,
            format!("cannot allocate string: {e}"),
        )
    })
}

fn out_bytes(env: &mut JNIEnv, b: &[u8]) -> R<jbyteArray> {
    env.byte_array_from_slice(b)
        .map(|v| v.into_raw())
        .map_err(|e| {
            Fail::Msg(
                bridge::code::GENERIC,
                format!("cannot allocate a {} byte array: {e}", b.len()),
            )
        })
}

fn bad_handle(msg: &'static str) -> Fail {
    Fail::Msg(bridge::code::BAD_HANDLE, msg.to_string())
}

// ------------------------------------------------------------------ lifecycle

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeVersion<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        out_string(env, luks_core::VERSION)
    })
}

/// Take ownership of a USB device already opened by Java.
///
/// `fd` comes from `UsbDeviceConnection.getFileDescriptor()` and remains owned
/// by Java. It must outlive the returned handle: Kotlin must not close the
/// connection until after `nativeCloseDevice`.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeOpenDevice<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    fd: jint,
    ep_in: jint,
    ep_out: jint,
    interface: jint,
    max_transfer: jint,
) -> jlong {
    guard(&mut env, 0, |_env| {
        if fd < 0 {
            return Err(Fail::Msg(
                bridge::code::TRANSPORT,
                format!("invalid file descriptor {fd}"),
            ));
        }
        let ep_in = u8::try_from(ep_in)
            .map_err(|_| Fail::Msg(bridge::code::TRANSPORT, format!("bad IN endpoint {ep_in}")))?;
        let ep_out = u8::try_from(ep_out).map_err(|_| {
            Fail::Msg(
                bridge::code::TRANSPORT,
                format!("bad OUT endpoint {ep_out}"),
            )
        })?;
        let interface = u8::try_from(interface).map_err(|_| {
            Fail::Msg(
                bridge::code::TRANSPORT,
                format!("bad interface number {interface}"),
            )
        })?;

        // SAFETY: the fd is owned by the Java `UsbDeviceConnection`; the contract
        // that it outlives this handle is documented on the Kotlin side and
        // enforced by `LuksDevice` closing in the reverse order.
        let handle = unsafe {
            bridge::open_usb_device(fd, ep_in, ep_out, interface, max_transfer.max(0) as usize)
        }?;
        Ok(bridge::into_raw(bridge::Payload::Device(handle)))
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeCloseDevice<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
) {
    guard(&mut env, (), |_env| {
        // SAFETY: freeing a handle we minted. The magic tag makes a double close
        // or a wrong-type close a no-op rather than a corrupt free.
        unsafe { bridge::drop_device(handle) };
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeCloseVolume<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
) {
    guard(&mut env, (), |_env| {
        // SAFETY: as above. The master key inside is zeroed by `Secret::drop`.
        unsafe { bridge::drop_volume(handle) };
        Ok(())
    })
}

// --------------------------------------------------------------------- device

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeDeviceInfo<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the device magic tag.
        let dev = unsafe { bridge::device_ref(handle) }.map_err(bad_handle)?;
        let json = dev.info_json();
        out_string(env, &json)
    })
}

/// Derive the master key and mount the filesystem. Seconds, and up to a
/// gigabyte of allocation — never call this on the UI thread, and hold a
/// foreground service while it runs.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeUnlock<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    partition_offset: jlong,
    password: JByteArray<'l>,
) -> jlong {
    guard(&mut env, 0, |env| {
        // SAFETY: validated against the device magic tag.
        let dev = unsafe { bridge::device_ref(handle) }.map_err(bad_handle)?;
        let offset = u64::try_from(partition_offset).map_err(|_| {
            Fail::Msg(
                bridge::code::GENERIC,
                format!("negative partition offset {partition_offset}"),
            )
        })?;

        // Copied out of the Java array, then owned by a Secret so it is zeroed
        // when this scope ends — including on the error path.
        let raw = env
            .convert_byte_array(&password)
            .map_err(|e| Fail::Msg(bridge::code::GENERIC, format!("cannot read password: {e}")))?;
        let secret = bridge::password_secret(raw);

        let volume = dev.unlock(offset, secret.expose())?;
        Ok(bridge::into_raw(bridge::Payload::Volume(volume)))
    })
}

// --------------------------------------------------------------------- volume

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeVolumeInfo<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let json = vol.info_json();
        out_string(env, &json)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeListDir<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    path: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let path = jstr(env, &path)?;
        let json = vol.list_dir_json(&path)?;
        out_string(env, &json)
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeFileInfo<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    path: JString<'l>,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let path = jstr(env, &path)?;
        let json = vol.file_info_json(&path)?;
        out_string(env, &json)
    })
}

/// Whole-file read. Fails rather than allocating past `max_bytes`, because the
/// result has to fit in the app heap as a `byte[]`.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeReadFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    path: JString<'l>,
    max_bytes: jlong,
) -> jbyteArray {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let path = jstr(env, &path)?;
        let cap = if max_bytes <= 0 {
            32 * 1024 * 1024
        } else {
            max_bytes as u64
        };
        let data = vol.read_file(&path, cap)?;
        out_bytes(env, &data)
    })
}

/// Read up to `len` bytes at `offset`. A shorter result means end of file.
///
/// Returns a fresh array rather than filling a caller-supplied one: writing into
/// a Java array from Rust means handing out a `&mut [i8]` aliasing JVM memory,
/// and the copy is not the bottleneck at USB speeds.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeReadChunk<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    path: JString<'l>,
    offset: jlong,
    len: jint,
) -> jbyteArray {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let path = jstr(env, &path)?;
        if offset < 0 || len <= 0 {
            return Err(Fail::Msg(
                bridge::code::GENERIC,
                format!("bad chunk request offset={offset} len={len}"),
            ));
        }
        let mut buf = vec![0u8; (len as usize).min(16 * 1024 * 1024)];
        let got = vol.read_chunk(&path, offset as u64, &mut buf)?;
        out_bytes(env, &buf[..got])
    })
}

/// SHA-256 a file by streaming it, returning JSON with the digest, byte count
/// and elapsed time.
///
/// This is the acceptance check for the stack end to end. It never materialises
/// the file, so it works on the 1 GiB test file that `nativeReadFile` refuses.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeSha256<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    path: JString<'l>,
    chunk_bytes: jint,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let path = jstr(env, &path)?;
        let json = vol.sha256_json(&path, chunk_bytes.max(0) as usize)?;
        out_string(env, &json)
    })
}

/// Time a raw block read: no decryption, no filesystem, just the transport.
///
/// The diagnostic that separates "our layers are slow" from "the link is
/// slow". Returns JSON including the transfer size the kernel actually allowed.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeBenchmarkRead<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    bytes: jlong,
    chunk_bytes: jint,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the device magic tag.
        let dev = unsafe { bridge::device_ref(handle) }.map_err(bad_handle)?;
        let json = dev.benchmark_json(bytes.max(0) as u64, chunk_bytes.max(0) as usize)?;
        out_string(env, &json)
    })
}

/// Time a raw block write: no encryption, no filesystem, no Java array.
///
/// The mirror of `nativeBenchmarkRead`, and the only remaining way to tell
/// whether the read/write gap on this phone is ours or the hardware's. Writes
/// past the end of every partition — see `benchmark_write_json`.
#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeBenchmarkWrite<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    bytes: jlong,
    chunk_bytes: jint,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        // SAFETY: validated against the device magic tag.
        let dev = unsafe { bridge::device_ref(handle) }.map_err(bad_handle)?;
        let json = dev.benchmark_write_json(bytes.max(0) as u64, chunk_bytes.max(0) as usize)?;
        out_string(env, &json)
    })
}

/// Measure AES-XTS and SHA-256 throughput in memory, with no USB involved.
///
/// Attributes the gap between the raw-read benchmark and the full-stack figure
/// to the layer actually responsible, instead of inferring it.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeSelfTest<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    mib: jint,
) -> jstring {
    guard(&mut env, std::ptr::null_mut(), |env| {
        let json = bridge::self_test_json(mib.max(1) as usize);
        out_string(env, &json)
    })
}

// ---------------------------------------------------------------------- write

/// Whether this library was built with the write path in it.
///
/// Present in **both** builds, and answering honestly in each. It exists so
/// Kotlin can ask rather than assume its own build flavour matches the `.so`
/// it happened to load — those are produced by different tools and can
/// disagree. Without it the only way to find out is to call `nativeWriteFile`
/// and catch `UnsatisfiedLinkError`, which is a poor way to learn a static
/// fact.
///
/// Nothing declares this on the Kotlin side yet; wiring it into `LuksNative`
/// is part of the Android pass, not this one.
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeWriteSupported<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jni::sys::jboolean {
    u8::from(cfg!(feature = "dangerous-write-support"))
}

/// Create a file in the volume's root directory. Returns its inode number.
///
/// **This symbol does not exist in a default build.** That is the point: a
/// release `.so` cannot be made to write by any argument, because there is
/// nothing in it to call. `nativeWriteSupported` above is how Kotlin finds
/// that out before trying.
///
/// Slow and blocking — it allocates, writes every block, and then flushes all
/// the way through the USB bridge. Same rule as `nativeUnlock`: never on the
/// UI thread.
#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeWriteFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    parent_path: JString<'l>,
    name: JString<'l>,
    data: JByteArray<'l>,
) -> jlong {
    guard(&mut env, 0, |env| {
        // SAFETY: validated against the volume magic tag.
        let vol = unsafe { bridge::volume_ref(handle) }.map_err(bad_handle)?;
        let parent_path = jstr(env, &parent_path)?;
        let name = jstr(env, &name)?;
        let bytes = env
            .convert_byte_array(&data)
            .map_err(|e| Fail::Msg(bridge::code::GENERIC, format!("cannot read data: {e}")))?;
        let ino = vol.write_file(&parent_path, &name, &bytes)?;
        Ok(ino as jlong)
    })
}

#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeBeginFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    volume: jlong,
    size: jlong,
) -> jlong {
    guard(&mut env, 0, |_env| {
        let vol = unsafe { bridge::volume_ref(volume) }.map_err(bad_handle)?;
        let size = u64::try_from(size)
            .map_err(|_| Fail::Msg(bridge::code::GENERIC, "negative file size".into()))?;
        let writer = vol.begin_file(size)?;
        Ok(bridge::into_raw(bridge::Payload::Writer(
            bridge::WriterHandle {
                volume_handle: volume,
                volume_id: vol.id,
                writer: std::sync::Mutex::new(Some(writer)),
            },
        )))
    })
}

#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeWriteChunk<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    volume: jlong,
    writer: jlong,
    data: JByteArray<'l>,
    len: jint,
) {
    guard(&mut env, (), |env| {
        let vol = unsafe { bridge::volume_ref(volume) }.map_err(bad_handle)?;
        let wh = unsafe { bridge::writer_ref(writer) }.map_err(bad_handle)?;
        if wh.volume_id != vol.id {
            return Err(bad_handle("writer belongs to another volume"));
        }
        let bytes = env
            .convert_byte_array(&data)
            .map_err(|e| Fail::Msg(bridge::code::GENERIC, format!("cannot read data: {e}")))?;
        let len = usize::try_from(len)
            .map_err(|_| Fail::Msg(bridge::code::GENERIC, "negative chunk length".into()))?;
        if len > bytes.len() {
            return Err(Fail::Msg(
                bridge::code::GENERIC,
                "chunk length exceeds buffer".into(),
            ));
        }
        let mut slot = wh.writer.lock().unwrap_or_else(|p| p.into_inner());
        let state = slot
            .as_mut()
            .ok_or_else(|| bad_handle("writer is finished or closed"))?;
        Ok(vol.write_file_chunk(state, &bytes[..len])?)
    })
}

#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeFinishFile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    volume: jlong,
    writer: jlong,
    parent_path: JString<'l>,
    name: JString<'l>,
) -> jlong {
    guard(&mut env, 0, |env| {
        let vol = unsafe { bridge::volume_ref(volume) }.map_err(bad_handle)?;
        let wh = unsafe { bridge::writer_ref(writer) }.map_err(bad_handle)?;
        if wh.volume_id != vol.id {
            return Err(bad_handle("writer belongs to another volume"));
        }
        let parent_path = jstr(env, &parent_path)?;
        let name = jstr(env, &name)?;
        let state = wh
            .writer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| bad_handle("writer is finished or closed"))?;
        let result = vol.finish_file(state, &parent_path, &name);
        unsafe { bridge::drop_writer(writer) };
        Ok(result? as jlong)
    })
}

#[cfg(feature = "dangerous-write-support")]
#[no_mangle]
pub extern "system" fn Java_dev_luksandroid_LuksNative_nativeCloseWriter<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    volume: jlong,
    writer: jlong,
) {
    guard(&mut env, (), |_env| {
        let vol = unsafe { bridge::volume_ref(volume) }.map_err(bad_handle)?;
        let wh = unsafe { bridge::writer_ref(writer) }.map_err(bad_handle)?;
        if wh.volume_id != vol.id {
            return Err(bad_handle("writer belongs to another volume"));
        }
        if let Some(state) = wh.writer.lock().unwrap_or_else(|p| p.into_inner()).take() {
            vol.abandon_file(state);
        }
        unsafe { bridge::drop_writer(writer) };
        Ok(())
    })
}
