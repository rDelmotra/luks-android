package dev.luksandroid

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Finding a mass-storage drive, getting permission for it, and handing its file
 * descriptor to the Rust transport.
 *
 * This is the whole Android-specific part of Phase 1. Everything below it —
 * Bulk-Only Transport framing, SCSI, partition tables, LUKS, ext4 — is the same
 * code a future Windows or macOS shell will run.
 */
object UsbMassStorage {

    /**
     * USB Mass Storage / SCSI transparent / Bulk-Only Transport.
     *
     * All three must match. A device answering class 8 with a different
     * protocol speaks something we do not implement (CBI, UAS), and treating it
     * as BOT would put malformed command blocks on the wire.
     */
    private const val SUBCLASS_SCSI = 6
    private const val PROTOCOL_BULK_ONLY = 80 // 0x50

    private const val ACTION_PERMISSION = "dev.luksandroid.USB_PERMISSION"

    data class Target(
        val device: UsbDevice,
        val usbInterface: UsbInterface,
        val endpointIn: UsbEndpoint,
        val endpointOut: UsbEndpoint,
    ) {
        val label: String
            get() = listOfNotNull(device.manufacturerName, device.productName)
                .joinToString(" ")
                .ifBlank { "USB device %04x:%04x".format(device.vendorId, device.productId) }
    }

    /** Every attached device that speaks BOT mass storage. */
    fun findTargets(context: Context): List<Target> {
        val manager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        return manager.deviceList.values.mapNotNull { describe(it) }
    }

    private fun describe(device: UsbDevice): Target? {
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            if (iface.interfaceClass != UsbConstants.USB_CLASS_MASS_STORAGE) continue
            if (iface.interfaceSubclass != SUBCLASS_SCSI) continue
            if (iface.interfaceProtocol != PROTOCOL_BULK_ONLY) continue

            var epIn: UsbEndpoint? = null
            var epOut: UsbEndpoint? = null
            for (e in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(e)
                if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
                if (ep.direction == UsbConstants.USB_DIR_IN) {
                    if (epIn == null) epIn = ep
                } else {
                    if (epOut == null) epOut = ep
                }
            }
            if (epIn != null && epOut != null) {
                return Target(device, iface, epIn, epOut)
            }
        }
        return null
    }

    fun hasPermission(context: Context, device: UsbDevice): Boolean {
        val manager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        return manager.hasPermission(device)
    }

    /**
     * Ask the user for access to [device], suspending until they answer.
     *
     * Two flags matter and both are easy to get wrong:
     * - The [PendingIntent] must be mutable. The system fills in the device and
     *   the grant result as extras; an immutable one silently never fires.
     * - The receiver must be registered `RECEIVER_NOT_EXPORTED` on API 33+, or
     *   registration throws.
     */
    suspend fun requestPermission(context: Context, device: UsbDevice): Boolean {
        val manager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        if (manager.hasPermission(device)) return true

        return suspendCancellableCoroutine { cont ->
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context, intent: Intent) {
                    if (intent.action != ACTION_PERMISSION) return
                    context.unregisterReceiver(this)
                    if (cont.isActive) {
                        cont.resume(intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
                    }
                }
            }

            val filter = IntentFilter(ACTION_PERMISSION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }

            cont.invokeOnCancellation { runCatching { context.unregisterReceiver(receiver) } }

            val pending = PendingIntent.getBroadcast(
                context,
                0,
                Intent(ACTION_PERMISSION).setPackage(context.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            manager.requestPermission(device, pending)
        }
    }

    /**
     * Open [target] and hand its descriptor to the Rust transport.
     *
     * `claimInterface(force = true)` is doing real work: Android's own
     * usb-storage driver will normally have bound the drive and may have mounted
     * it. Without the force flag the kernel driver keeps the interface and the
     * `USBDEVFS_CLAIMINTERFACE` on the Rust side fails with EBUSY. With it, the
     * driver is detached first — which also means the drive disappears from the
     * system file manager while this app holds it.
     *
     * Claiming here *and* in Rust is deliberate and not a double-claim bug:
     * usbfs tracks claims per file descriptor, and it is the same descriptor, so
     * the second claim is a no-op. Rust claims anyway so the crate is correct on
     * its own terms rather than depending on this caller.
     */
    fun open(context: Context, target: Target, maxTransfer: Int = 0): LuksDevice {
        val manager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        val connection = manager.openDevice(target.device)
            ?: throw LuksException(
                "could not open ${target.label} (permission revoked, or unplugged)",
                LuksException.TRANSPORT,
            )

        try {
            if (!connection.claimInterface(target.usbInterface, true)) {
                throw LuksException(
                    "another driver holds the interface and would not release it",
                    LuksException.TRANSPORT,
                )
            }
            val handle = LuksNative.nativeOpenDevice(
                connection.fileDescriptor,
                target.endpointIn.address,
                target.endpointOut.address,
                target.usbInterface.id,
                maxTransfer,
            )
            return LuksDevice(handle, connection, target.usbInterface)
        } catch (t: Throwable) {
            // The LuksDevice was never constructed, so nothing else will free
            // these. Leaking a claimed interface leaves the drive unusable to
            // the whole system until it is physically unplugged.
            runCatching { connection.releaseInterface(target.usbInterface) }
            runCatching { connection.close() }
            throw t
        }
    }
}
