package dev.luksandroid

import android.app.Application
import dev.luksandroid.session.LuksSession
import dev.luksandroid.session.LuksSessionLifecycle
import dev.luksandroid.session.UsbDetachReceiver

/**
 * Custom Application class initializing session tracking, lifecycle callbacks,
 * and USB detach broadcast listeners.
 */
class LuksApp : Application() {

    lateinit var sessionLifecycle: LuksSessionLifecycle
        private set

    override fun onCreate() {
        super.onCreate()
        Trace.i("LuksApp", "Application initializing; LuksSession initialized")
        
        sessionLifecycle = LuksSessionLifecycle(LuksSession)
        registerActivityLifecycleCallbacks(sessionLifecycle)
        registerComponentCallbacks(sessionLifecycle)
        UsbDetachReceiver.register(this, LuksSession)
    }

    override fun onTerminate() {
        super.onTerminate()
        UsbDetachReceiver.unregister(this)
        unregisterActivityLifecycleCallbacks(sessionLifecycle)
        unregisterComponentCallbacks(sessionLifecycle)
    }
}
