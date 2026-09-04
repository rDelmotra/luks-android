package dev.luksandroid.documents

import android.os.Handler
import android.os.HandlerThread

/**
 * Dedicated singleton [HandlerThread] to handle [android.os.ProxyFileDescriptorCallback]
 * execution off binder and main threads.
 */
object LuksProxyHandlerThread {
    private val thread: HandlerThread = HandlerThread("luks-proxy-fd").apply {
        start()
    }

    val handler: Handler = Handler(thread.looper)
}
