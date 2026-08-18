package dev.luksandroid.session

import android.content.ComponentCallbacks2
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Bug 1 regression coverage: physical-hardware run 2026-08-18 showed the app locking the
 * session the moment it was backgrounded (`TRIM_MEMORY_UI_HIDDEN`, level 20), throwing away
 * a 78-second unlock. notes/feature-session-lifecycle.md §3 specifies idle timeout + explicit
 * lock + unplug as the relock triggers and explicitly rejects screen-off/backgrounding relock
 * as "hostile to long transfers". These tests pin that policy at the [LuksSessionLifecycle]
 * layer: UI_HIDDEN must never lock; only levels that mean the process is about to be killed
 * (COMPLETE, RUNNING_CRITICAL) may.
 */
class LuksSessionLifecycleTest {

    private lateinit var testScope: CoroutineScope
    private lateinit var session: SessionController
    private lateinit var lifecycle: LuksSessionLifecycle

    @Before
    fun setUp() {
        testScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        session = SessionController(scope = testScope)
        lifecycle = LuksSessionLifecycle(session = session, scope = testScope)
    }

    @After
    fun tearDown() {
        testScope.cancel()
    }

    private suspend fun awaitLocked() {
        withTimeout(2000) {
            while (session.state.value !is SessionState.Locked) {
                delay(10)
            }
        }
    }

    @Test
    fun uiHidden_level20_doesNotLock() = runBlocking {
        session.startUnlockedForTest()

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN)

        // Give any (incorrect) lock() launch a real chance to land before asserting
        // it didn't happen.
        delay(300)
        assertTrue(
            "Backgrounding (UI_HIDDEN) must never lock the session",
            session.state.value is SessionState.Unlocked,
        )
    }

    @Test
    fun uiHidden_level20_doesNotLock_evenWithNoActivitiesStarted() = runBlocking {
        // Regression guard: the old policy conditioned UI_HIDDEN locking on
        // `startedActivities <= 0`, which is exactly the state a backgrounded app is
        // normally in. Locking here was the actual observed bug, so it must not
        // depend on activity bookkeeping at all — the constant is now unreachable via
        // UI_HIDDEN by construction, but pin the behavior with zero started activities
        // explicitly since that's the real-world case that broke.
        session.startUnlockedForTest()
        assertEquals(0, lifecycle.activeActivityCount)

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN)

        delay(300)
        assertTrue(session.state.value is SessionState.Unlocked)
    }

    @Test
    fun trimComplete_level80_locks() = runBlocking {
        session.startUnlockedForTest()

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_COMPLETE)

        awaitLocked()
        assertEquals(SessionState.Locked, session.state.value)
    }

    @Test
    fun runningCritical_level15_locks() = runBlocking {
        session.startUnlockedForTest()

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL)

        awaitLocked()
        assertEquals(SessionState.Locked, session.state.value)
    }

    @Test
    fun runningLow_level10_doesNotLock() = runBlocking {
        // Sanity check on the other RUNNING_* levels: only RUNNING_CRITICAL is severe
        // enough to drop the key; RUNNING_LOW/MODERATE are not.
        session.startUnlockedForTest()

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW)

        delay(300)
        assertTrue(session.state.value is SessionState.Unlocked)
    }

    @Test
    fun activeLease_blocksTrimLock_evenAtCriticalLevel() = runBlocking {
        session.startUnlockedForTest()
        val leaseStarted = kotlinx.coroutines.CompletableDeferred<Unit>()
        val releaseLease = kotlinx.coroutines.CompletableDeferred<Unit>()
        val leaseJob = testScope.launch(Dispatchers.Default) {
            session.withLease {
                leaseStarted.complete(Unit)
                releaseLease.await()
            }
        }
        leaseStarted.await()

        lifecycle.onTrimMemory(ComponentCallbacks2.TRIM_MEMORY_COMPLETE)
        delay(300)
        assertTrue(
            "Must not lock out from under an active lease",
            session.state.value is SessionState.Unlocked,
        )

        releaseLease.complete(Unit)
        leaseJob.join()
    }
}
