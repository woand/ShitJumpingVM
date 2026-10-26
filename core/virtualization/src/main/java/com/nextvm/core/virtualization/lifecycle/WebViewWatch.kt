package com.nextvm.core.virtualization.lifecycle

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * v46/v47: witness for the WebView provider double-registration
 * crash (launch64/65: HomeWebFragment's WebView died in
 * WebViewChromiumFactoryProvider.<init> with "Already registered a
 * list of actions in this process").
 *
 * Established facts going in: the WebView APK odex load sits at
 * fork+1.30s in both launch64 and launch65, on the guest main
 * thread, inside the guest startup band — an early, deterministic
 * touch. The v46 watch missed it twice over: it started at bind
 * COMPLETE, and it filtered for webkit/chromium frames in the Java
 * stack, while an APK class load is performed by ART natively —
 * the triggering Java stack may contain no webview frames at all.
 *
 * v47 therefore: starts at bindApplication ENTRY (before any guest
 * code runs); samples the main thread every 40ms; for the first
 * 5s (v48; was 3.5s) records EVERY distinct main-thread stack (dedup
 * by hash, capped) so the stack current at the odex second names the
 * trigger whatever it contains; stamps every line with wall-clock
 * time to correlate with the logcat odex line; emits a 500ms
 * heartbeat so a dead watch is distinguishable from no event;
 * polls WebViewFactory.sProviderInstance throughout (10s window),
 * recording transitions; after 5s records only webview-touching
 * stacks, as v46 did. Stack depth recorded is 42 frames (v48; v47's
 * 18 cut off the caller below WebViewFactory.getProviderClass in
 * launch66).
 *
 * Sampling uses Thread.getStackTrace() on the main thread only:
 * it never calls getAllStackTraces (see DiagSuspendGate /
 * launch58). Once per guest process; output
 * webviewwatch-<pid>.log next to the other guest diagnostics.
 */
object WebViewWatch {

    private val started = AtomicBoolean(false)

    private const val PHASE1_MS = 5_000L
    private const val TOTAL_MS = 10_000L
    private const val MAX_STACKS = 90

    fun schedule(packageName: String, filesDir: File) {
        if (packageName.isBlank()) return
        if (!started.compareAndSet(false, true)) return
        Thread {
            try {
                runWatch(filesDir)
            } catch (t: Throwable) {
                // a witness must never disturb the guest
            }
        }.apply {
            name = "webview-watch"
            isDaemon = true
            start()
        }
    }

    private fun runWatch(filesDir: File) {
        val pid = android.os.Process.myPid()
        val out = File(filesDir, "webviewwatch-$pid.log")
        val mainThread = android.os.Looper.getMainLooper().thread
        val providerField = try {
            val f = Class.forName("android.webkit.WebViewFactory")
                .getDeclaredField("sProviderInstance")
            f.isAccessible = true
            f
        } catch (t: Throwable) {
            null
        }

        fun providerState(): String {
            if (providerField == null) return "field-missing"
            val v = try {
                providerField.get(null)
            } catch (t: Throwable) {
                return "read-error"
            }
            return if (v == null) {
                "null"
            } else {
                "set(${v.javaClass.name}@${System.identityHashCode(v)})"
            }
        }

        val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
        val t0 = System.nanoTime()
        fun elapsedMs() = (System.nanoTime() - t0) / 1_000_000
        fun stamp() = "[${fmt.format(Date())} +${elapsedMs()}ms]"

        out.bufferedWriter().use { w ->
            fun line(s: String) {
                w.write(s)
                w.newLine()
                w.flush()
            }
            var lastProvider = providerState()
            line("${stamp()} watch start pid=$pid provider=$lastProvider")
            val seenStacks = HashSet<Int>()
            var lastWvSig = ""
            var lastHeartbeat = 0L
            while (elapsedMs() < TOTAL_MS) {
                val now = elapsedMs()
                val ps = providerState()
                if (ps != lastProvider) {
                    line("${stamp()} provider: $lastProvider -> $ps")
                    lastProvider = ps
                }
                val stack = mainThread.stackTrace
                if (now - lastHeartbeat >= 500) {
                    lastHeartbeat = now
                    val top = stack.firstOrNull()
                    line(
                        "${stamp()} hb provider=$ps mainTop=" +
                            (top?.let { "${it.className}.${it.methodName}" }
                                ?: "<empty>")
                    )
                }
                // v48: 42 frames, not 18 — in launch66 the chain
                // DexFile..LoadedApk.getClassLoader filled exactly
                // 18 frames and cut off the caller directly below
                // WebViewFactory.getProviderClass.
                val full = stack.take(42).joinToString("\n") {
                    "    at ${it.className}.${it.methodName}"
                }
                val sig = full.hashCode()
                if (now < PHASE1_MS) {
                    if (seenStacks.add(sig) &&
                        seenStacks.size <= MAX_STACKS
                    ) {
                        line("${stamp()} main stack:")
                        line(full)
                    }
                } else {
                    val touchesWebView = stack.any {
                        it.className.contains("webkit") ||
                            it.className.contains(
                                "chromium", ignoreCase = true
                            )
                    }
                    if (touchesWebView) {
                        val s = sig.toString()
                        if (s != lastWvSig) {
                            lastWvSig = s
                            line(
                                "${stamp()} main thread in WebView " +
                                    "code, provider=$ps"
                            )
                            line(full)
                        }
                    } else if (lastWvSig.isNotEmpty()) {
                        line(
                            "${stamp()} main thread left WebView " +
                                "code, provider=$ps"
                        )
                        lastWvSig = ""
                    }
                }
                Thread.sleep(if (now < PHASE1_MS) 40 else 120)
            }
            line("${stamp()} watch end provider=${providerState()}")
        }
    }
}
