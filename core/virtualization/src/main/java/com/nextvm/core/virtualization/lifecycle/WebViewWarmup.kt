package com.nextvm.core.virtualization.lifecycle

import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * v49: active repair + witness for the WebView provider
 * double-registration crash (third breakpoint).
 *
 * Bytecode-proven mechanism (WebView APK classes.dex, build
 * 810300513, disassembled offline): WebViewChromiumFactoryProvider
 * .initialize() first checks a process-static registry — obfuscated
 * WV.i62's static singleton (WV.j62) field `a`, the registered
 * action array (WV.f62[]). Non-null -> throws IllegalStateException
 * "Already registered a list of actions in this process". The
 * registration itself happens inside that same initialize(), so a
 * getProvider() that registers and then fails at a later step (and
 * whose failure is swallowed by a tolerant caller) leaves the
 * process poisoned: WebViewFactory.sProviderInstance stays null,
 * yet every later construction trips the guard. Launch64-67 show
 * exactly that shape: a deterministic getProviderClass touch at
 * bind+0.65s, provider never cached, home WebView crashes.
 *
 * This warmup runs once per guest process, on its own thread,
 * scheduled at bind complete:
 *  1. Read and log the registry state (via the provider
 *     classloader) BEFORE touching anything.
 *  2. Reflectively call WebViewFactory.getProvider() and log the
 *     full outcome. Success -> the provider is cached for the
 *     whole process; the guest's WebViews reuse it.
 *  3. If the call trips the already-registered guard, clear the
 *     registry (WV.i62.a instance's `a` field -> null; names are
 *     specific to this WebView build and every step fails soft)
 *     and retry getProvider() once, logging the full outcome.
 *  4. Any other failure is logged with its complete stack: that
 *     exception is the datum missing for three launches and
 *     decides the true environmental fix.
 *
 * v50 addition: launch68 caught the first construction's real
 * failure — RuntimeException "No data directory found for package
 * com.nextvm.app" from ContextImpl.getDataDir(), reached via
 * getSharedPreferences() inside the provider constructor: the
 * guest Application's backing LoadedApk reports no data dir, so
 * construction dies after registration, before caching. Before
 * calling getProvider(), the warmup now probes that LoadedApk
 * (aInfo.dataDir, cached mDataDir/mDataDirFile, an actual
 * getDataDir() call on the terminal ContextImpl) and repairs the
 * cached fields in place to the guest data directory
 * (filesDir.parent) — the same directory the engine's path
 * injection already writes into mApplicationInfo, whose cached
 * LoadedApk fields it never refreshes.
 *
 * Output: webviewwarm-<pid>.log next to the other guest
 * diagnostics. Unicom only.
 */
object WebViewWarmup {

    private val started = AtomicBoolean(false)

    private const val GUARD_MESSAGE =
        "Already registered a list of actions in this process"

    fun schedule(packageName: String, filesDir: File) {
        if (packageName != "com.sinovatech.unicom.ui") return
        if (!started.compareAndSet(false, true)) return
        Thread {
            try {
                runWarmup(filesDir)
            } catch (t: Throwable) {
                // never disturb the guest
            }
        }.apply {
            name = "webview-warmup"
            isDaemon = true
            start()
        }
    }

    private fun runWarmup(filesDir: File) {
        val pid = android.os.Process.myPid()
        val out = File(filesDir, "webviewwarm-$pid.log")
        val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
        fun stamp() = "[${fmt.format(Date())}]"
        out.bufferedWriter().use { w ->
            fun line(s: String) {
                w.write(s)
                w.newLine()
                w.flush()
            }
            fun render(t: Throwable): String {
                val sw = StringWriter()
                t.printStackTrace(PrintWriter(sw))
                return sw.toString()
            }
            fun chainHasGuard(t: Throwable): Boolean {
                var c: Throwable? = t
                while (c != null) {
                    if (c.message?.contains(GUARD_MESSAGE) == true) {
                        return true
                    }
                    c = c.cause
                }
                return false
            }

            line("${stamp()} warmup start pid=$pid")
            probeAndRepairDataDir { line("${stamp()} $it") }
            line("${stamp()} provider before: ${providerState()}")
            val cl = glueClassLoader { line("${stamp()} $it") }
            line(
                "${stamp()} registry before: " +
                    (cl?.let { registryState(it) } ?: "no-classloader")
            )

            // First attempt: warm the provider ourselves.
            try {
                val provider = callGetProvider()
                line(
                    "${stamp()} getProvider #1 OK: " +
                        "${provider?.javaClass?.name}@" +
                        "${System.identityHashCode(provider)}"
                )
                line("${stamp()} provider after: ${providerState()}")
                return
            } catch (t: Throwable) {
                line("${stamp()} getProvider #1 FAILED:")
                line(render(t))
                if (!chainHasGuard(t)) {
                    line(
                        "${stamp()} not the guard error; " +
                            "no reset attempted"
                    )
                    return
                }
            }

            // Guard tripped: the registry is poisoned. Clear + retry.
            if (cl == null) {
                line("${stamp()} no glue classloader; cannot reset")
                return
            }
            line(
                "${stamp()} registry at reset: ${registryState(cl)}"
            )
            if (!clearRegistry(cl)) {
                line("${stamp()} registry reset FAILED")
                return
            }
            line("${stamp()} registry cleared; retrying getProvider")
            try {
                val provider = callGetProvider()
                line(
                    "${stamp()} getProvider #2 OK: " +
                        "${provider?.javaClass?.name}@" +
                        "${System.identityHashCode(provider)}"
                )
                line("${stamp()} provider after: ${providerState()}")
            } catch (t: Throwable) {
                line("${stamp()} getProvider #2 FAILED:")
                line(render(t))
            }
        }
    }

    /**
     * v50: locate the LoadedApk(s) backing the guest Application,
     * log their data-dir state, and repair the cached dir fields.
     *
     * Candidates: Application.mLoadedApk (set by Application
     * .attach() from the attach context's ContextImpl) and the
     * terminal ContextImpl's mPackageInfo found by walking the
     * Application's base-context chain. The provider failure goes
     * through ContextImpl.getDataDir(), i.e. through the terminal
     * ContextImpl, so that one's getDataDir() is probed directly.
     */
    private fun probeAndRepairDataDir(log: (String) -> Unit) {
        try {
            val atClass = Class.forName("android.app.ActivityThread")
            val app = atClass.getMethod("currentApplication")
                .invoke(null) as? android.app.Application
            if (app == null) {
                log("probe: currentApplication=null")
                return
            }
            log("probe: currentApplication=${app.javaClass.name}")

            // Terminal context at the end of the base chain.
            var terminal: Any = app
            while (terminal is android.content.ContextWrapper) {
                terminal = terminal.baseContext ?: break
            }
            val impl = terminal as? android.content.Context
            log(
                "probe: terminal context=${terminal.javaClass.name} " +
                    "getDataDir: " +
                    (impl?.let { tryGetDataDir(it) } ?: "n/a")
            )
            log("probe: app getDataDir: ${tryGetDataDir(app)}")

            val candidates = LinkedHashSet<Any>()
            findFieldInHierarchy(app.javaClass, "mLoadedApk")?.let { f ->
                f.isAccessible = true
                f.get(app)?.let {
                    candidates.add(it)
                    log("probe: LoadedApk via Application.mLoadedApk")
                }
            }
            if (impl != null) {
                findFieldInHierarchy(impl.javaClass, "mPackageInfo")
                    ?.let { f ->
                        f.isAccessible = true
                        f.get(impl)?.let {
                            candidates.add(it)
                            log("probe: LoadedApk via ContextImpl.mPackageInfo")
                        }
                    }
            }
            if (candidates.isEmpty()) {
                log("probe: no LoadedApk candidate found")
                return
            }

            val filesDir = try {
                app.getFilesDir()
            } catch (t: Throwable) {
                null
            }
            val targetDir = filesDir?.parent
            log("probe: filesDir=$filesDir targetDataDir=$targetDir")

            for (la in candidates) {
                val aInfo = readField(la, "mApplicationInfo")
                    as? android.content.pm.ApplicationInfo
                log(
                    "probe: LoadedApk@${System.identityHashCode(la)} " +
                        "aInfo.pkg=${aInfo?.packageName} " +
                        "aInfo.dataDir=${aInfo?.dataDir} " +
                        "mDataDir=${readField(la, "mDataDir")} " +
                        "mDataDirFile=${readField(la, "mDataDirFile")}"
                )
                if (targetDir == null) continue
                if (aInfo != null && aInfo.dataDir != targetDir) {
                    aInfo.dataDir = targetDir
                    log("repair: aInfo.dataDir -> $targetDir")
                }
                setFieldLogged(la, "mDataDir", targetDir, log)
                setFieldLogged(la, "mDataDirFile", File(targetDir), log)
                setFieldLogged(
                    la, "mCredentialProtectedDataDirFile",
                    File(targetDir), log
                )
                setFieldLogged(
                    la, "mDeviceProtectedDataDirFile",
                    File(targetDir), log
                )
            }
            log(
                "probe: terminal getDataDir after repair: " +
                    (impl?.let { tryGetDataDir(it) } ?: "n/a")
            )
        } catch (t: Throwable) {
            log("probe/repair failed: $t")
        }
    }

    private fun tryGetDataDir(ctx: android.content.Context): String {
        return try {
            "ok(${ctx.getDataDir()})"
        } catch (t: Throwable) {
            "THROWS ${t.javaClass.simpleName}: ${t.message}"
        }
    }

    private fun readField(target: Any, name: String): Any? {
        val f = findFieldInHierarchy(target.javaClass, name)
            ?: return null
        f.isAccessible = true
        return f.get(target)
    }

    private fun setFieldLogged(
        target: Any,
        name: String,
        value: Any,
        log: (String) -> Unit
    ) {
        val f = findFieldInHierarchy(target.javaClass, name)
        if (f == null) {
            log("repair: field $name absent")
            return
        }
        f.isAccessible = true
        f.set(target, value)
        log("repair: $name -> $value")
    }

    private fun findFieldInHierarchy(
        cls: Class<*>,
        name: String
    ): java.lang.reflect.Field? {
        var c: Class<*>? = cls
        while (c != null) {
            try {
                return c.getDeclaredField(name)
            } catch (e: NoSuchFieldException) {
                c = c.superclass
            }
        }
        return null
    }

    private fun providerState(): String {
        return try {
            val f = Class.forName("android.webkit.WebViewFactory")
                .getDeclaredField("sProviderInstance")
            f.isAccessible = true
            val v = f.get(null)
            if (v == null) {
                "null"
            } else {
                "set(${v.javaClass.name}@${System.identityHashCode(v)})"
            }
        } catch (t: Throwable) {
            "read-error($t)"
        }
    }

    private fun callGetProvider(): Any? {
        val factory = Class.forName("android.webkit.WebViewFactory")
        val m = try {
            factory.getMethod("getProvider")
        } catch (e: NoSuchMethodException) {
            factory.getDeclaredMethod("getProvider").apply {
                isAccessible = true
            }
        }
        return m.invoke(null)
    }

    /** Classloader of the WebView glue classes, via the provider
     *  class WebViewFactory resolves. Loading the class does not
     *  run initialize() (that is an instance method called from
     *  the provider constructor), so this is observation-only. */
    private fun glueClassLoader(log: (String) -> Unit): ClassLoader? {
        return try {
            val factory = Class.forName("android.webkit.WebViewFactory")
            val m = factory.getDeclaredMethod("getProviderClass")
            m.isAccessible = true
            val cls = m.invoke(null) as? Class<*>
            if (cls == null) {
                log("getProviderClass returned null")
                null
            } else {
                log("provider class: ${cls.name}")
                cls.classLoader
            }
        } catch (t: Throwable) {
            log("getProviderClass failed: $t")
            null
        }
    }

    /** "absent" (glue not loaded / names changed), "empty", or
     *  "poisoned(n actions)" for the WV.i62 registry singleton. */
    private fun registryState(cl: ClassLoader): String {
        return try {
            val i62 = Class.forName("WV.i62", false, cl)
            val holderField = i62.getDeclaredField("a")
            holderField.isAccessible = true
            val holder = holderField.get(null) ?: return "holder-null"
            val arrayField = holder.javaClass.getDeclaredField("a")
            arrayField.isAccessible = true
            val arr = arrayField.get(holder)
            if (arr == null) {
                "empty"
            } else {
                "poisoned(len=${java.lang.reflect.Array.getLength(arr)})"
            }
        } catch (t: Throwable) {
            "absent($t)"
        }
    }

    private fun clearRegistry(cl: ClassLoader): Boolean {
        return try {
            val i62 = Class.forName("WV.i62", false, cl)
            val holderField = i62.getDeclaredField("a")
            holderField.isAccessible = true
            val holder = holderField.get(null) ?: return false
            val arrayField = holder.javaClass.getDeclaredField("a")
            arrayField.isAccessible = true
            arrayField.set(holder, null)
            true
        } catch (t: Throwable) {
            false
        }
    }
}
