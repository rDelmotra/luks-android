package dev.luksandroid.session

import android.app.Activity
import android.app.Application
import android.content.ComponentCallbacks2
import android.content.res.Configuration
import android.os.Bundle
import dev.luksandroid.Trace
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tracks activity lifecycle and memory trim levels to coordinate orderly
 * volume locking and master key destruction when UI is destroyed or under memory pressure.
 */
class LuksSessionLifecycle(
    private val session: SessionController = LuksSession,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) : Application.ActivityLifecycleCallbacks, ComponentCallbacks2 {

    private val startedActivities = AtomicInteger(0)
    private val aliveActivities = AtomicInteger(0)

    val activeActivityCount: Int get() = startedActivities.get()
    val aliveActivityCount: Int get() = aliveActivities.get()

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
        aliveActivities.incrementAndGet()
    }

    override fun onActivityStarted(activity: Activity) {
        startedActivities.incrementAndGet()
    }

    override fun onActivityResumed(activity: Activity) {}

    override fun onActivityPaused(activity: Activity) {}

    override fun onActivityStopped(activity: Activity) {
        startedActivities.decrementAndGet()
    }

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

    override fun onActivityDestroyed(activity: Activity) {
        val remaining = aliveActivities.decrementAndGet()
        Trace.i("LuksSessionLifecycle", "onActivityDestroyed: remaining activities=$remaining, active leases=${session.activeLeases}")
        if (remaining <= 0 && session.activeLeases == 0) {
            scope.launch {
                if (aliveActivities.get() <= 0 && session.activeLeases == 0) {
                    Trace.i("LuksSessionLifecycle", "All activities destroyed with 0 active leases: locking session")
                    session.lock()
                }
            }
        }
    }

    @Suppress("DEPRECATION")
    override fun onTrimMemory(level: Int) {
        Trace.i("LuksSessionLifecycle", "onTrimMemory level=$level, startedActivities=${startedActivities.get()}, activeLeases=${session.activeLeases}")
        // notes/feature-session-lifecycle.md §3: idle timeout + explicit lock + unplug are
        // the relock triggers; screen-off/backgrounding relock was rejected by name as
        // "hostile to long transfers". TRIM_MEMORY_UI_HIDDEN fires on every backgrounding
        // (switch apps, screen off, another app's dialog) and is NOT a security event — it
        // must never lock, regardless of activity count. Only levels that mean the process
        // is genuinely about to be killed (COMPLETE, RUNNING_CRITICAL) drop the key here;
        // the idle timeout remains the primary relock mechanism.
        val shouldLock = when (level) {
            ComponentCallbacks2.TRIM_MEMORY_COMPLETE,
            ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL -> true
            else -> false
        }

        if (shouldLock && session.activeLeases == 0) {
            scope.launch {
                if (session.activeLeases == 0) {
                    Trace.i("LuksSessionLifecycle", "TrimMemory ($level): locking session and dropping master key")
                    session.lock()
                }
            }
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {}

    @Suppress("DEPRECATION")
    @Deprecated("Deprecated in ComponentCallbacks")
    override fun onLowMemory() {
        Trace.i("LuksSessionLifecycle", "onLowMemory received: activeLeases=${session.activeLeases}")
        if (session.activeLeases == 0) {
            scope.launch {
                if (session.activeLeases == 0) {
                    session.lock()
                }
            }
        }
    }
}
