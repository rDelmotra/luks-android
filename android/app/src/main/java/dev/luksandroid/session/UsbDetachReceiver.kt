package dev.luksandroid.session

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import dev.luksandroid.Trace

/**
 * BroadcastReceiver listening for system USB disconnect events.
 *
 * When the drive is detached, immediately transitions [LuksSession] to
 * [SessionState.Detached], tearing down volume handles and master key in memory.
 */
class UsbDetachReceiver(
    private val session: LuksSession = LuksSession,
) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == UsbManager.ACTION_USB_DEVICE_DETACHED) {
            val detachedDev = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
            }
            val active = session.activeUsbDevice
            if (active != null && detachedDev != null) {
                val matches = (detachedDev.deviceId == active.deviceId) ||
                    (detachedDev.vendorId == active.vendorId && detachedDev.productId == active.productId)
                if (!matches) {
                    Trace.i("UsbDetachReceiver", "Ignoring detach for unrelated USB device")
                    return
                }
            }
            Trace.i("UsbDetachReceiver", "Active USB device detached")
            session.notifyDeviceDetached()
        }
    }

    companion object {
        @Volatile
        private var registeredReceiver: UsbDetachReceiver? = null

        fun register(context: Context, session: LuksSession = LuksSession): UsbDetachReceiver {
            val receiver = UsbDetachReceiver(session)
            val filter = IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
            registeredReceiver = receiver
            return receiver
        }

        fun unregister(context: Context) {
            registeredReceiver?.let {
                runCatching { context.unregisterReceiver(it) }
                registeredReceiver = null
            }
        }
    }
}
