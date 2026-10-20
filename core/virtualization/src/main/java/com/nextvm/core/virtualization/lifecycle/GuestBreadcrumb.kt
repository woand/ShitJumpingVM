package com.nextvm.core.virtualization.lifecycle

import timber.log.Timber
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * v36 guest lifecycle breadcrumb (steps 2+3 of the four-step plan).
 *
 * Rationale: every prior experiment says the splash stall completes
 * silently — no crash, no second activity, no IPC. Two silent-failure
 * shapes remain untested:
 *  (2) an exception thrown inside a lifecycle step and swallowed by
 *      one of the engine's catch sites (each of which historically
 *      logged a one-line message with NO stack), aborting the step
 *      mid-flight while the framework believes it completed;
 *  (3) an init step that is simply never called (provider onCreate,
 *      FPSDK collection, ...), invisible without an ordered event log.
 *
 * GuestBreadcrumb is an ordered, timestamped, file-persisted event
 * log for ONE guest bind (unicom only). Events are buffered in memory
 * until the guest files dir is known (attachFile, called right after
 * the guest Application exists), then flushed and appended to
 * breadcrumb-<pid>.log next to the stackdump/hijacktrace files.
 * Every swallowed exception on a lifecycle path is recorded here
 * WITH its full stack trace. Diagnostics must never disturb the
 * guest: all entry points swallow their own failures.
 */
object GuestBreadcrumb {

    private const val TAG = "BootCrumb"
    private const val MAX_BUFFER_LINES = 4000

    @Volatile private var active = false
    @Volatile private var t0 = 0L
    @Volatile private var file: File? = null

    private val lock = Any()
    private val buffer = ArrayList<String>()

    /** Begin a breadcrumb session for [packageName] (unicom only). */
    fun begin(packageName: String) {
        if (packageName != "com.sinovatech.unicom.ui") return
        synchronized(lock) {
            active = true
            t0 = System.nanoTime()
            buffer.clear()
            file = null
        }
        log("breadcrumb begin pkg=$packageName pid=" + android.os.Process.myPid())
    }

    /** Point the log at the guest files dir; flush buffered events. */
    fun attachFile(filesDir: File) {
        if (!active) return
        try {
            val f = File(filesDir, "breadcrumb-" + android.os.Process.myPid() + ".log")
            synchronized(lock) {
                file = f
                if (buffer.isNotEmpty()) {
                    val pending = ArrayList(buffer)
                    buffer.clear()
                    try {
                        f.appendText(pending.joinToString("\n", postfix = "\n"))
                    } catch (_: Throwable) {
                    }
                }
            }
        } catch (_: Throwable) {
        }
    }

    fun log(event: String) {
        if (!active) return
        try {
            val elapsedMs = if (t0 == 0L) 0L else (System.nanoTime() - t0) / 1_000_000L
            val line = "[+" + elapsedMs + "ms] [" + Thread.currentThread().name +
                "] " + event
            Timber.tag(TAG).i("%s", line)
            synchronized(lock) {
                val f = file
                if (f == null) {
                    if (buffer.size < MAX_BUFFER_LINES) buffer.add(line)
                } else {
                    try {
                        f.appendText(line + "\n")
                    } catch (_: Throwable) {
                    }
                }
            }
        } catch (_: Throwable) {
        }
    }

    /** Record an exception WITH full stack — the anti-swallow log. */
    fun logThrowable(event: String, t: Throwable) {
        if (!active) return
        try {
            val sw = StringWriter()
            t.printStackTrace(PrintWriter(sw))
            log(event + " <" + t.javaClass.name + ": " + t.message + ">\n" +
                sw.toString().trimEnd())
        } catch (_: Throwable) {
        }
    }
}
