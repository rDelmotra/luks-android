package dev.luksandroid

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/**
 * A foreground service held for the duration of an unlock.
 *
 * It does no work. Its entire purpose is to change the process's `oom_adj` so
 * Android's low-memory killer will not take the app during the Argon2
 * allocation — which for the developer's real drive is **1 GiB**, the single
 * largest thing this app ever does and the top-rated risk in the project since
 * before any code existed.
 *
 * Without this, an LMK kill mid-derivation looks like an arbitrary crash: no
 * exception, no stack trace, the process simply gone. With it, the app is in
 * the same protection class as a music player and is killed only under genuine
 * memory pressure.
 *
 * It deliberately does *not* run the unlock itself. Doing that would mean
 * binding, callbacks and cross-process state for no benefit — the risk being
 * mitigated is memory-killer priority, which is a property of the process, not
 * of which thread the work runs on.
 */
class UnlockService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel(this)

        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.unlock_notification_title))
            .setContentText(getString(R.string.unlock_notification_text))
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()

        // minSdk is 29, so the type-carrying overload always exists. The type
        // must match android:foregroundServiceType in the manifest or API 34+
        // throws rather than starting.
        startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)

        // Not sticky: if the process dies mid-unlock there is nothing to
        // resume. The master key was never derived and the USB handle is gone.
        return START_NOT_STICKY
    }

    companion object {
        private const val CHANNEL_ID = "unlock"
        private const val NOTIFICATION_ID = 1

        private fun ensureChannel(context: Context) {
            val manager = context.getSystemService(NotificationManager::class.java)
            if (manager.getNotificationChannel(CHANNEL_ID) != null) return
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.unlock_channel_name),
                    // LOW: no sound, no heads-up. The notification exists to
                    // justify the foreground state, not to interrupt anyone.
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = context.getString(R.string.unlock_channel_description)
                    setShowBadge(false)
                }
            )
        }

        /**
         * Run [block] with the service held.
         *
         * `finally` rather than a plain stop: if the unlock throws — a wrong
         * password is an *expected* outcome, not an exceptional one — the
         * service must still come down, or the app sits in the foreground
         * state indefinitely with a stale notification.
         */
        suspend fun <T> holding(context: Context, block: suspend () -> T): T {
            val intent = Intent(context, UnlockService::class.java)
            context.startForegroundService(intent)
            return try {
                block()
            } finally {
                context.stopService(intent)
            }
        }
    }
}
