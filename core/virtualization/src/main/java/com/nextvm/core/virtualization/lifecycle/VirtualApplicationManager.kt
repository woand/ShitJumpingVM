package com.nextvm.core.virtualization.lifecycle

import android.app.Application
import android.app.Instrumentation
import android.content.ContentProvider
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ProviderInfo
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.common.findMethod
import com.nextvm.core.common.runSafe
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * VirtualApplicationManager — Manages guest app Application lifecycle.
 *
 * This is the MOST critical missing piece. It handles:
 * - Instantiating guest app's custom Application subclass via DexClassLoader
 * - Calling Application.attachBaseContext(virtualContext)
 * - Calling Application.onCreate()
 * - Managing Application lifecycle per guest app instance
 * - ContentProvider auto-init (AndroidX Startup, WorkManager, Firebase via ContentProvider.onCreate())
 * - AppComponentFactory support (Android 9+)
 * - handleBindApplication() mirror — simulating what real Android does when binding an app
 *
 * Mirrors the flow from:
 *   ActivityThread.handleBindApplication() in frameworks/base/core/java/android/app/ActivityThread.java
 *
 * Flow:
 *   1. Create LoadedApk equivalent (set up ClassLoader, Resources)
 *   2. Create AppComponentFactory (Android 9+)
 *   3. Instantiate Application class
 *   4. Install ContentProviders (BEFORE Application.onCreate)
 *   5. Call Application.attachBaseContext()
 *   6. Call Application.onCreate()
 */
@Singleton
class VirtualApplicationManager @Inject constructor() {

    companion object {
        private const val TAG = "VAppLifecycle"
    }

    private var initialized = false
    private lateinit var appContext: android.content.Context

    fun initialize(context: android.content.Context) {
        if (initialized) return
        appContext = context.applicationContext
        initialized = true
        Timber.tag(TAG).i("VirtualApplicationManager initialized — Application lifecycle ready")
    }

    /**
     * Holds state for a living guest Application.
     */
    data class ApplicationRecord(
        val instanceId: String,
        val packageName: String,
        val application: Application,
        val classLoader: ClassLoader,
        val applicationClassName: String?,
        val contentProviders: MutableList<ContentProvider> = mutableListOf(),
        val startTime: Long = System.currentTimeMillis(),
        var state: ApplicationState = ApplicationState.CREATED
    )

    enum class ApplicationState {
        CREATED,
        ATTACHED,
        PROVIDERS_INSTALLED,
        RUNNING,
        TERMINATED
    }

    // instanceId -> ApplicationRecord
    private val applications = ConcurrentHashMap<String, ApplicationRecord>()

    /**
     * Full bind-application flow — mirrors ActivityThread.handleBindApplication().
     *
     * Order (from real Android source):
     *   1. Set up ApplicationInfo
     *   2. Create ClassLoader (already done by VirtualEngine)
     *   3. Set up Resources (handled by VirtualResourceManager)
     *   4. Create Instrumentation
     *   5. Create Application instance via AppComponentFactory or reflection
     *   6. Install ContentProviders (BEFORE onCreate!)
     *   7. Call Instrumentation.callApplicationOnCreate()
     *
     * @param instanceId Unique instance identifier
     * @param packageName Guest app package name
     * @param applicationClassName Fully qualified Application class (null = android.app.Application)
     * @param apkPath Path to the guest APK
     * @param classLoader DexClassLoader for the guest app
     * @param virtualContext Sandboxed context wrapping the guest identity
     * @param providerNames List of ContentProvider class names to initialize
     * @param providerAuthorities Map of provider class name -> authority string
     * @return The created Application or null on failure
     */
    fun bindApplication(
        instanceId: String,
        packageName: String,
        applicationClassName: String?,
        apkPath: String,
        classLoader: ClassLoader,
        virtualContext: Context,
        providerNames: List<String> = emptyList(),
        providerAuthorities: Map<String, String> = emptyMap(),
        providerMetaData: Map<String, Bundle> = emptyMap(),
        frameworkLoadedApk: Any? = null
    ): Application? {
        // Check if already bound
        val existing = applications[instanceId]
        if (existing != null && existing.state != ApplicationState.TERMINATED) {
            Timber.tag(TAG).d("Application already bound for $instanceId, returning existing")
            return existing.application
        }

        Timber.tag(TAG).i("bindApplication: $packageName ($instanceId)")
        Timber.tag(TAG).d("  applicationClass: ${applicationClassName ?: "android.app.Application"}")
        Timber.tag(TAG).d("  providers: ${providerNames.size}")
        GuestBreadcrumb.begin(packageName)
        GuestBreadcrumb.log("bind start instance=$instanceId appClass=" +
            (applicationClassName ?: "android.app.Application") +
            " providers=" + providerNames.size +
            " frameworkLoadedApk=" + (frameworkLoadedApk != null))
        // v47: start the WebView witness HERE, at bind entry — v46
        // started it at bind complete and missed the guest startup
        // band where the early WebView touch lives (fork+1.3s).
        // virtualContext.filesDir is the guest files dir. The
        // bind-complete schedule() calls below become no-ops.
        WebViewWatch.schedule(packageName, virtualContext.filesDir)

        var legacyPrevInstr: Instrumentation? = null
        try {
            // B2: framework-native bind — when a framework LoadedApk is
            // available for this guest, the Application is created and
            // attached by the framework itself instead of being
            // hand-assembled onto the host's (patched) LoadedApk.
            if (frameworkLoadedApk != null) {
                val fwApp = bindViaFrameworkLoadedApk(
                    instanceId = instanceId,
                    packageName = packageName,
                    loadedApk = frameworkLoadedApk,
                    virtualContext = virtualContext,
                    providerNames = providerNames,
                    providerAuthorities = providerAuthorities,
                    providerMetaData = providerMetaData
                )
                if (fwApp != null) {
                    GuestBreadcrumb.attachFile(fwApp.filesDir)
                    registerBreadcrumbCallbacks(fwApp)
                    GuestBreadcrumb.log("bind complete (framework path)")
                    scheduleGuestStackDumps()
                    scheduleHijackTrace(packageName)
                    DexMemDump.schedule(packageName, fwApp.filesDir)
                    StateProbe.schedule(packageName, fwApp.filesDir)
                    WebViewWatch.schedule(packageName, fwApp.filesDir)
                    WebViewWarmup.schedule(packageName, fwApp.filesDir)
                    return fwApp
                }
                GuestBreadcrumb.log("framework path returned null, falling back to legacy bind")
                // fall through to the legacy bind path
            }

            // Step 1: Prepare ApplicationInfo on the virtual context
            val appInfo = buildApplicationInfo(packageName, apkPath, virtualContext)

            // Step 2: Create Application instance
            val application = createApplication(
                instanceId = instanceId,
                packageName = packageName,
                applicationClassName = applicationClassName,
                classLoader = classLoader,
                virtualContext = virtualContext,
                appInfo = appInfo
            ) ?: return null

            // Step 3: Create ApplicationRecord
            val record = ApplicationRecord(
                instanceId = instanceId,
                packageName = packageName,
                application = application,
                classLoader = classLoader,
                applicationClassName = applicationClassName
            )
            applications[instanceId] = record

            // Step 3.5: Set the guest Application on VirtualContext so that
            // getApplicationContext() returns the real Application instance.
            // This is CRITICAL for AndroidX libraries (ProcessLifecycleInitializer,
            // WorkManager, Firebase) which cast getApplicationContext() to Application.
            if (virtualContext is com.nextvm.core.sandbox.VirtualContext) {
                virtualContext.setGuestApplication(application)
            }

            // Step 4: Attach base context
            // v35: same stock-init cover as the framework path —
            // hijack's initailise runs inside this attach.
            legacyPrevInstr = swapInStockInstrumentation(packageName)
            GuestBreadcrumb.log("legacy attachBaseContext enter")
            attachBaseContext(application, virtualContext)
            GuestBreadcrumb.log("legacy attachBaseContext exit")
            record.state = ApplicationState.ATTACHED
            Timber.tag(TAG).d("Application.attachBaseContext() complete")

            // Step 4.5: Patch LoadedApk.mApplication to the guest Application.
            // ContextImpl.getApplicationContext() returns LoadedApk.getApplication()
            // which normally returns the HOST Application. By patching mApplication,
            // even code that bypasses our ContextWrapper chain (e.g., framework-internal
            // calls to ContextImpl directly) will get the guest Application.
            patchLoadedApkApplication(virtualContext, application)

            // Step 5: Install ContentProviders BEFORE Application.onCreate()
            // This is critical — AndroidX Startup, WorkManager, Firebase all use
            // ContentProviders that must be initialized before the Application.
            if (providerNames.isNotEmpty()) {
                initContentProviders(
                    instanceId = instanceId,
                    providers = providerNames,
                    authorities = providerAuthorities,
                    classLoader = classLoader,
                    virtualContext = virtualContext,
                    application = application,
                    providerMetaData = providerMetaData
                )
                record.state = ApplicationState.PROVIDERS_INSTALLED
                Timber.tag(TAG).d("ContentProviders installed: ${providerNames.size}")
            }

            // Step 6: Call Application.onCreate()
            callApplicationOnCreate(application)
            record.state = ApplicationState.RUNNING
            Timber.tag(TAG).i("Application.onCreate() complete for $packageName")
            restoreInstrumentation(legacyPrevInstr)

            GuestBreadcrumb.attachFile(application.filesDir)
            registerBreadcrumbCallbacks(application)
            GuestBreadcrumb.log("bind complete (legacy path)")
            scheduleGuestStackDumps()
            scheduleHijackTrace(packageName)
            DexMemDump.schedule(packageName, application.filesDir)
            StateProbe.schedule(packageName, application.filesDir)
            WebViewWatch.schedule(packageName, application.filesDir)
            WebViewWarmup.schedule(packageName, application.filesDir)
            return application

        } catch (e: Exception) {
            restoreInstrumentation(legacyPrevInstr)
            GuestBreadcrumb.logThrowable("bind FAILED (legacy/framework outer catch)", e)
            Timber.tag(TAG).e(e, "Failed to bind application for $packageName ($instanceId)")
            applications.remove(instanceId)
            return null
        }
    }

    /**
     * v36 step 3: engine-side ActivityLifecycleCallbacks on the guest
     * Application — an activity breadcrumb independent of the
     * instrumentation chain (created/started/resumed/... per activity).
     */
    private fun registerBreadcrumbCallbacks(app: Application) {
        try {
            app.registerActivityLifecycleCallbacks(
                object : Application.ActivityLifecycleCallbacks {
                    override fun onActivityCreated(
                        a: android.app.Activity, b: android.os.Bundle?
                    ) = GuestBreadcrumb.log("cb onActivityCreated " + a.javaClass.name)

                    override fun onActivityStarted(a: android.app.Activity) =
                        GuestBreadcrumb.log("cb onActivityStarted " + a.javaClass.name)

                    override fun onActivityResumed(a: android.app.Activity) =
                        GuestBreadcrumb.log("cb onActivityResumed " + a.javaClass.name)

                    override fun onActivityPaused(a: android.app.Activity) =
                        GuestBreadcrumb.log("cb onActivityPaused " + a.javaClass.name)

                    override fun onActivityStopped(a: android.app.Activity) =
                        GuestBreadcrumb.log("cb onActivityStopped " + a.javaClass.name)

                    override fun onActivitySaveInstanceState(
                        a: android.app.Activity, b: android.os.Bundle
                    ) = GuestBreadcrumb.log("cb onActivitySaveInstanceState " + a.javaClass.name)

                    override fun onActivityDestroyed(a: android.app.Activity) =
                        GuestBreadcrumb.log("cb onActivityDestroyed " + a.javaClass.name)
                })
            GuestBreadcrumb.log("engine breadcrumb callbacks registered on " + app.javaClass.name)
        } catch (e: Throwable) {
            GuestBreadcrumb.logThrowable("register breadcrumb callbacks FAILED", e)
        }
    }

    // ==================== Guest stack diagnostics ====================
    // One-shot per process: after a guest Application binds, dump all
    // thread stacks (+ the main Looper's pending messages) at
    // +0.3/+0.7/+1.2/+2/+3/+8/+20s into a stackdump-<pid>.log under the
    // Application's filesDir (for a framework-bound guest that resolves
    // to the guest sandbox files dir; readable via run-as).
    // Exists to answer "the guest UI is up but never advances — what
    // is it waiting on?" with the actual Java frames instead of
    // black-box guessing.

    @Volatile private var stackDumpsScheduled = false

    private fun scheduleGuestStackDumps() {
        if (stackDumpsScheduled) return
        stackDumpsScheduled = true
        Thread {
            try {
                val hostApp = Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null)
                    as? android.app.Application ?: return@Thread
                val out = java.io.File(
                    hostApp.filesDir, "stackdump-${android.os.Process.myPid()}.log"
                )
                // Cadence (v29): logcat comparison against a real
                // device localized the guest's init-pipeline stall to
                // the first ~1.5s after process start (bind lands at
                // ~+0.45s), so sample densely across bind+0.3..+3s
                // to catch threads mid-flight at the stall moment;
                // +8s/+20s remain as steady-state anchors.
                val marks = listOf(
                    300L to "t+0.3s",
                    700L to "t+0.7s",
                    1_200L to "t+1.2s",
                    2_000L to "t+2s",
                    3_000L to "t+3s",
                    8_000L to "t+8s",
                    20_000L to "t+20s"
                )
                var elapsed = 0L
                for ((at, label) in marks) {
                    val wait = at - elapsed
                    if (wait > 0) Thread.sleep(wait)
                    elapsed = at
                    dumpGuestStacks(out, label)
                }
            } catch (_: Throwable) {
                // diagnostics must never disturb the guest
            }
        }.apply { isDaemon = true; name = "nv-stackdump" }.start()
    }

    private fun dumpGuestStacks(out: java.io.File, label: String) {
        val sb = StringBuilder()
        sb.append("==== ").append(label).append(" ====\n")
        // Main Looper pending messages first: a scheduled-but-never-
        // fired navigation message (or an empty queue) is the fastest
        // discriminator for splash stalls.
        try {
            val queue = android.os.Looper.getMainLooper().queue
            val mf = queue.javaClass.getDeclaredField("mMessages")
            mf.isAccessible = true
            var msg = mf.get(queue)
            var n = 0
            sb.append("main looper queue:\n")
            while (msg != null && n < 20) {
                val cls = msg.javaClass
                val whenF = cls.getDeclaredField("when").apply { isAccessible = true }
                val cbF = cls.getDeclaredField("callback").apply { isAccessible = true }
                val tgtF = cls.getDeclaredField("target").apply { isAccessible = true }
                val whatF = cls.getDeclaredField("what").apply { isAccessible = true }
                val nextF = cls.getDeclaredField("next").apply { isAccessible = true }
                sb.append("  when=+").append(
                    (whenF.getLong(msg) - android.os.SystemClock.uptimeMillis()) / 1000.0
                ).append("s what=").append(whatF.getInt(msg))
                    .append(" callback=").append(cbF.get(msg)?.javaClass?.name)
                    .append(" target=").append(tgtF.get(msg)?.javaClass?.name)
                    .append('\n')
                msg = nextF.get(msg)
                n++
            }
            if (n == 0) sb.append("  (empty)\n")
        } catch (e: Throwable) {
            sb.append("main looper queue: <").append(e.javaClass.simpleName).append(">\n")
        }
        // v42: serialize the suspension on DiagSuspendGate.
        // getAllStackTraces() suspends every thread; in launch58
        // this dump (+8s) and StateProbe's census (+7s) suspended
        // concurrently and ART's suspend watchdog aborted the guest
        // (SuspendThreadByPeer timeout). StateProbe no longer
        // suspends at all; this gate keeps any future diagnostic
        // suspender from overlapping this one.
        val traces = synchronized(DiagSuspendGate.lock) {
            Thread.getAllStackTraces()
        }
        // Main thread first, then the rest (Rx/pool/player threads are
        // the interesting waiters).
        val ordered = traces.keys.sortedWith(
            compareBy({ if (it.name == "main") 0 else 1 }, { it.name })
        )
        for (t in ordered) {
            sb.append("--- \"").append(t.name).append("\" ").append(t.state).append('\n')
            val frames = traces[t] ?: continue
            for ((i, f) in frames.withIndex()) {
                if (i >= 30) break
                sb.append("    at ").append(f.toString()).append('\n')
            }
        }
        try {
            out.appendText(sb.toString())
        } catch (_: Throwable) {
        }
    }

    // ==================== Hijack SDK completion trace (v33) ====================
    // v34 adds the discriminating experiment: after each sample, if
    // ActivityThread.mInstrumentation is hijack's ProxyInstrumentation,
    // swap it (and every existing Activity's mInstrumentation) back to
    // the proxy's oriInstrumentation (the engine's NextVmInstrumentation).
    // v33 proved the proxy sits in its "hijack suspected" state
    // permanently in the sandbox (oriClassType=0); if the splash then
    // advances to MainActivity, the proxy's extracted callbacks were
    // the gate. If nothing changes, the hijack line is closed.
    // One-shot per process, unicom only. Static analysis showed the
    // guest's App.attachBaseContext() calls
    // com.sdk.hijack.api.HijackSDK.initailise(Application) first thing,
    // which (a) sets hidden-API exemptions via reflection, (b) wraps
    // ActivityThread.mInstrumentation in its ProxyInstrumentation,
    // (c) registers ActivityLifecycleCallbacks, then sets its own
    // isRegisterActivityLifecycleCallbacks flag as the last step.
    // Whether all of that actually completes inside the sandbox is
    // invisible from outside (registerContext swallows failures), so
    // at +1/+4/+12s after bind we reflectively read back the end
    // state: the flag, ProxyInstrumentation.instance, the live
    // ActivityThread/Application instrumentation objects, the
    // registered lifecycle callbacks, and each running Activity's
    // mInstrumentation. Log tag "HijackTrace" + a
    // hijacktrace-<pid>.log next to the stackdumps.

    @Volatile private var hijackTraceScheduled = false

    // ==================== v35: stock-init experiment ====================
    // v34 only removed the hijack proxy AFTER bind; it never changed
    // what the proxy wrapped. On a real device ActivityThread's
    // instrumentation is a stock android.app.Instrumentation, so
    // hijack's ProxyInstrumentation classifies its ori as type 1
    // ("not hijacked"). In the sandbox it wraps the engine's
    // NextVmInstrumentation (type 0) and any verdict latched at
    // ProxyInstrumentation.<init> / register time — during
    // App.attachBaseContext, long before any post-bind unwrap — is
    // already fixed. v35 therefore swaps a stock Instrumentation into
    // ActivityThread.mInstrumentation for the whole guest early-init
    // window (attachBaseContext -> ContentProviders ->
    // Application.onCreate) and restores the previous instance
    // afterwards: NextVmInstrumentation is load-bearing for activity
    // creation (newActivity classloader resolution, pre-create
    // injection), so it cannot stay replaced — but the classification
    // moment and everything guest init reads from ActivityThread see
    // the faithful real-device configuration. Validity check built
    // in: at restore time AT is expected to hold hijack's
    // ProxyInstrumentation (registerContext wrapped the stock
    // instance); the sampler then reads oriInstrumentation /
    // oriClassType from ProxyInstrumentation.instance — expect
    // android.app.Instrumentation / 1 (v33/v34 read
    // NextVmInstrumentation / 0). Unicom only.

    @Volatile private var stockInitExperiment = false
    @Volatile private var stockInitNote = "not-run"

    // v36: both discriminating mutations are concluded experiments
    // (v34 unwrap: falsified launch50; v35 stock-init: falsified
    // launch52). v36 is observe-only — a clean baseline plus the
    // breadcrumb — so both default OFF. Flip the const to re-run one.
    private val STOCK_INIT_ENABLED = false
    private val UNWRAP_ENABLED = false

    private fun swapInStockInstrumentation(packageName: String): Instrumentation? {
        if (!STOCK_INIT_ENABLED) {
            stockInitNote = "disabled (v36 observe-only baseline)"
            return null
        }
        if (packageName != "com.sinovatech.unicom.ui") return null
        return try {
            val atCls = Class.forName("android.app.ActivityThread")
            val at = atCls.getMethod("currentActivityThread").invoke(null)
                ?: return null
            val f = fieldOf(atCls, "mInstrumentation")
            val prev = f.get(at) as? Instrumentation
            f.set(at, Instrumentation())
            stockInitExperiment = true
            stockInitNote = "swapped prev=" + (prev?.javaClass?.name ?: "null") +
                " -> android.app.Instrumentation (stock)"
            Timber.tag("HijackTrace").i("v35 stock-init: %s", stockInitNote)
            prev
        } catch (e: Throwable) {
            stockInitNote = "swap FAILED <" + e.javaClass.simpleName + "> " + e.message
            Timber.tag("HijackTrace").w("v35 stock-init: %s", stockInitNote)
            null
        }
    }

    private fun restoreInstrumentation(prev: Instrumentation?) {
        if (prev == null) return
        try {
            val atCls = Class.forName("android.app.ActivityThread")
            val at = atCls.getMethod("currentActivityThread").invoke(null)
                ?: return
            val f = fieldOf(atCls, "mInstrumentation")
            val during = f.get(at)
            f.set(at, prev)
            stockInitNote += "; at restore AT was " +
                (during?.javaClass?.name ?: "null") + ", prev restored"
            Timber.tag("HijackTrace").i(
                "v35 stock-init restore: AT during init=%s",
                during?.javaClass?.name)
        } catch (e: Throwable) {
            stockInitNote += "; restore FAILED <" + e.javaClass.simpleName + ">"
        }
    }

    private fun scheduleHijackTrace(packageName: String) {
        if (packageName != "com.sinovatech.unicom.ui") return
        if (hijackTraceScheduled) return
        hijackTraceScheduled = true
        Thread {
            try {
                val hostApp = Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null)
                    as? android.app.Application ?: return@Thread
                val out = java.io.File(
                    hostApp.filesDir, "hijacktrace-${android.os.Process.myPid()}.log"
                )
                val marks = listOf(
                    1_000L to "t+1s", 4_000L to "t+4s",
                    12_000L to "t+12s", 25_000L to "t+25s"
                )
                var elapsed = 0L
                for ((at, label) in marks) {
                    val wait = at - elapsed
                    if (wait > 0) Thread.sleep(wait)
                    elapsed = at
                    sampleHijackState(out, label)
                    unwrapHijackProxy(out, label)
                }
            } catch (_: Throwable) {
                // diagnostics must never disturb the guest
            }
        }.apply { isDaemon = true; name = "nv-hijacktrace" }.start()
    }

    private fun fieldOf(cls: Class<*>, name: String): java.lang.reflect.Field {
        var c: Class<*>? = cls
        while (c != null) {
            try {
                return c.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
        throw NoSuchFieldException(name + " on " + cls.name)
    }

    private fun sampleHijackState(out: java.io.File, label: String) {
        val sb = StringBuilder()
        sb.append("==== ").append(label).append(" ====\n")
        fun line(s: String) {
            sb.append(s).append('\n')
            Timber.tag("HijackTrace").i("%s %s", label, s)
        }
        try {
            val atCls = Class.forName("android.app.ActivityThread")
            val at = atCls.getMethod("currentActivityThread").invoke(null)
            if (at == null) {
                line("ActivityThread: null")
                out.appendText(sb.toString())
                return
            }
            // (b) live ActivityThread instrumentation
            val atInstr = fieldOf(atCls, "mInstrumentation").get(at)
            line("ActivityThread.mInstrumentation = " + (atInstr?.javaClass?.name ?: "null"))
            line("v35 stock-init: " + stockInitNote)
            // guest Application + its classloader (loads the SDK classes)
            val app = atCls.getMethod("getApplication").invoke(at)
                as? android.app.Application
            line("Application = " + (app?.javaClass?.name ?: "null"))
            val guestCl = app?.javaClass?.classLoader
            // (c) registered lifecycle callbacks on the Application
            if (app != null) {
                try {
                    val cbs = fieldOf(Class.forName("android.app.Application"),
                        "mActivityLifecycleCallbacks").get(app) as? java.util.ArrayList<*>
                    if (cbs == null) {
                        line("lifecycleCallbacks = null")
                    } else {
                        line("lifecycleCallbacks.size = " + cbs.size)
                        for (cb in cbs) line("  cb: " + (cb?.javaClass?.name ?: "null"))
                    }
                } catch (e: Throwable) {
                    line("lifecycleCallbacks: <" + e.javaClass.simpleName + ">")
                }
            }
            // SDK end-state statics, read through the guest classloader
            if (guestCl != null) {
                try {
                    val sdk = Class.forName("com.sdk.hijack.api.HijackSDK", false, guestCl)
                    val done = fieldOf(sdk, "isRegisterActivityLifecycleCallbacks")
                        .getBoolean(null)
                    line("HijackSDK.isRegisterActivityLifecycleCallbacks = " + done)
                } catch (e: Throwable) {
                    line("HijackSDK flag: <" + e.javaClass.simpleName + ">")
                }
                try {
                    val pi = Class.forName(
                        "com.sdk.hijack.base.ProxyInstrumentation", false, guestCl)
                    val inst = fieldOf(pi, "instance").get(null)
                    line("ProxyInstrumentation.instance = " +
                        (if (inst == null) "null" else "set(sameAsAT=" + (inst === atInstr) + ")"))
                    if (inst != null) {
                        try {
                            val ori = fieldOf(pi, "oriInstrumentation").get(inst)
                            val typ = fieldOf(pi, "oriClassType").getInt(inst)
                            line("  oriInstrumentation = " +
                                (ori?.javaClass?.name ?: "null") + " oriClassType = " + typ)
                        } catch (e: Throwable) {
                            line("  ori: <" + e.javaClass.simpleName + ">")
                        }
                    }
                } catch (e: Throwable) {
                    line("ProxyInstrumentation.instance: <" + e.javaClass.simpleName + ">")
                }
            }
            // per-Activity instrumentation (registerActivity's target)
            try {
                val actsAny = fieldOf(atCls, "mActivities").get(at)
                if (actsAny == null) {
                    line("mActivities = null")
                } else {
                    val entries = actsAny.javaClass.getMethod("entrySet")
                        .invoke(actsAny) as java.util.Set<*>
                    line("mActivities.size = " + entries.size)
                    for (entry in entries) {
                        if (entry == null) continue
                        val rec = entry.javaClass.getMethod("getValue")
                            .invoke(entry) ?: continue
                        val act = fieldOf(rec.javaClass, "activity").get(rec) ?: continue
                        val ai = try {
                            fieldOf(Class.forName("android.app.Activity"),
                                "mInstrumentation").get(act)
                        } catch (e: Throwable) {
                            null
                        }
                        line("  activity " + act.javaClass.name +
                            " mInstrumentation = " + (ai?.javaClass?.name ?: "null"))
                    }
                }
            } catch (e: Throwable) {
                line("mActivities: <" + e.javaClass.simpleName + ">")
            }
            // v36 anchor A: framework provider map — did the framework
            // install any providers itself (the engine installs the
            // guest's manually; anything here came via the framework)?
            try {
                val pmAny = fieldOf(atCls, "mProviderMap").get(at)
                if (pmAny == null) {
                    line("mProviderMap = null")
                } else {
                    val entries = pmAny.javaClass.getMethod("entrySet")
                        .invoke(pmAny) as java.util.Set<*>
                    line("mProviderMap.size = " + entries.size)
                    for (entry in entries) {
                        if (entry == null) continue
                        val rec = entry.javaClass.getMethod("getValue")
                            .invoke(entry) ?: continue
                        val local = try {
                            fieldOf(rec.javaClass, "mLocalProvider").get(rec)
                        } catch (e: Throwable) {
                            null
                        }
                        line("  provider local=" +
                            (local?.javaClass?.name ?: "null"))
                    }
                }
            } catch (e: Throwable) {
                line("mProviderMap: <" + e.javaClass.simpleName + ">")
            }
            // v36 anchor B: is the FPSDK native lib even loaded in
            // this process? fetchDeviceId cannot have run otherwise.
            // (libDexHelper as a positive control — it always loads.)
            try {
                val maps = java.io.File("/proc/self/maps").readText()
                line("maps libUnicomFPSDK.so loaded = " +
                    maps.contains("libUnicomFPSDK"))
                line("maps libDexHelper.so loaded = " +
                    maps.contains("libDexHelper"))
            } catch (e: Throwable) {
                line("maps: <" + e.javaClass.simpleName + ">")
            }
        } catch (e: Throwable) {
            line("sample failed: <" + e.javaClass.simpleName + "> " + e.message)
        }
        try {
            out.appendText(sb.toString())
        } catch (_: Throwable) {
        }
    }

    private fun unwrapHijackProxy(out: java.io.File, label: String) {
        val sb = StringBuilder()
        fun line(s: String) {
            sb.append(s).append('\n')
            Timber.tag("HijackTrace").i("%s unwrap: %s", label, s)
        }
        if (stockInitExperiment) {
            line("skipped, v35 stock-init experiment active")
            try { out.appendText(sb.toString()) } catch (_: Throwable) { }
            return
        }
        if (!UNWRAP_ENABLED) {
            line("unwrap disabled (v36 observe-only baseline)")
            try { out.appendText(sb.toString()) } catch (_: Throwable) { }
            return
        }
        try {
            val atCls = Class.forName("android.app.ActivityThread")
            val at = atCls.getMethod("currentActivityThread").invoke(null)
            if (at == null) {
                line("skip, ActivityThread null")
                out.appendText(sb.toString())
                return
            }
            val instrF = fieldOf(atCls, "mInstrumentation")
            val cur = instrF.get(at)
            if (cur == null ||
                cur.javaClass.name != "com.sdk.hijack.base.ProxyInstrumentation"
            ) {
                line("skip, AT.mInstrumentation = " + (cur?.javaClass?.name ?: "null"))
                out.appendText(sb.toString())
                return
            }
            val ori = fieldOf(cur.javaClass, "oriInstrumentation").get(cur)
            if (ori == null) {
                line("abort, oriInstrumentation is null")
                out.appendText(sb.toString())
                return
            }
            instrF.set(at, ori)
            line("AT.mInstrumentation ProxyInstrumentation -> " + ori.javaClass.name)
            try {
                val actsAny = fieldOf(atCls, "mActivities").get(at)
                val entries = actsAny.javaClass.getMethod("entrySet")
                    .invoke(actsAny) as java.util.Set<*>
                val aiF = fieldOf(Class.forName("android.app.Activity"),
                    "mInstrumentation")
                for (entry in entries) {
                    if (entry == null) continue
                    val rec = entry.javaClass.getMethod("getValue")
                        .invoke(entry) ?: continue
                    val act = fieldOf(rec.javaClass, "activity").get(rec) ?: continue
                    val ai = aiF.get(act)
                    if (ai != null && ai.javaClass.name ==
                        "com.sdk.hijack.base.ProxyInstrumentation"
                    ) {
                        aiF.set(act, ori)
                        line("activity " + act.javaClass.name +
                            " mInstrumentation -> ori")
                    }
                }
            } catch (e: Throwable) {
                line("activities swap: <" + e.javaClass.simpleName + ">")
            }
        } catch (e: Throwable) {
            line("unwrap failed: <" + e.javaClass.simpleName + "> " + e.message)
        }
        try {
            out.appendText(sb.toString())
        } catch (_: Throwable) {
        }
    }

    /**
     * Framework-native bind (B2): build the guest's app ContextImpl
     * from its framework LoadedApk and let LoadedApk.makeApplication()
     * create + attach the Application — the same construction a real
     * app goes through in ActivityThread.handleBindApplication().
     *
     * The legacy path instead instantiates the Application by
     * reflection and attaches it to a VirtualContext whose underlying
     * LoadedApk is the HOST's (with guest paths patched into it). Any
     * code inspecting the Application's LoadedApk/ContextImpl object
     * graph (packers do) sees the seam. Here mLoadedApk, the resources,
     * the data dirs and the class loader are all genuinely the guest's
     * own framework objects.
     *
     * Providers and onCreate keep the same ordering as the legacy path.
     * Returns null if the framework construction fails; the caller
     * then falls back to the legacy bind.
     */
    private fun bindViaFrameworkLoadedApk(
        instanceId: String,
        packageName: String,
        loadedApk: Any,
        virtualContext: Context,
        providerNames: List<String>,
        providerAuthorities: Map<String, String>,
        providerMetaData: Map<String, Bundle> = emptyMap()
    ): Application? {
        var prevInstr: Instrumentation? = null
        return try {
            val atClass = Class.forName("android.app.ActivityThread")
            val activityThread = atClass.getMethod("currentActivityThread").invoke(null)
                ?: return null
            val loadedApkClass = Class.forName("android.app.LoadedApk")

            // Identity toward the real system must be the HOST's.
            // The framework LoadedApk carries the guest package in
            // mPackageName, and every ContextImpl created from it
            // derives mOpPackageName + mAttributionSource from that
            // field — so the guest's first Settings/DeviceConfig
            // provider call reaches the system with the guest package
            // as calling identity and dies on
            // AppOpsManager.checkPackage (guest pkg does not belong
            // to the host uid) with a SecurityException. Mirror the
            // LoadedApk-clone path's defense (see ActivityThreadHook):
            // patch mPackageName to the host package BEFORE any
            // ContextImpl is created from this LoadedApk. The
            // LoadedApk stays registered under the guest name in
            // ActivityThread.mPackages, and guest code keeps seeing
            // the guest package through the VirtualContext wrapper.
            val hostPkg = (virtualContext as? android.content.ContextWrapper)
                ?.baseContext?.packageName
                ?: runCatching {
                    atClass.getMethod("currentApplication").invoke(null)
                        as? android.app.Application
                }.getOrNull()?.packageName
            if (hostPkg != null && hostPkg != packageName) {
                runCatching {
                    val pkgField = loadedApkClass.getDeclaredField("mPackageName")
                    pkgField.isAccessible = true
                    pkgField.set(loadedApk, hostPkg)
                    Timber.tag(TAG).i(
                        "Patched framework LoadedApk mPackageName " +
                            "$packageName -> $hostPkg (system-facing identity)"
                    )
                }.onFailure {
                    Timber.tag(TAG).w(it, "Failed to patch LoadedApk mPackageName")
                }
            }

            val contextImplClass = Class.forName("android.app.ContextImpl")
            val createAppContext = contextImplClass.getDeclaredMethod(
                "createAppContext", atClass, loadedApkClass
            )
            createAppContext.isAccessible = true
            val appContext = createAppContext.invoke(null, activityThread, loadedApk) as Context

            val guestClassLoader = loadedApkClass.getMethod("getClassLoader")
                .invoke(loadedApk) as? ClassLoader ?: return null

            // Same CheckJNI guard as the legacy attach path.
            disableCheckJniForGuest()

            // v35: cover the guest early-init window with a stock
            // Instrumentation (see swapInStockInstrumentation). The
            // window runs from here (makeApplication triggers
            // App.attachBaseContext, where hijack's initailise reads
            // AT.mInstrumentation) through initContentProviders and
            // callApplicationOnCreate below; restored after that.
            prevInstr = swapInStockInstrumentation(packageName)

            GuestBreadcrumb.log("framework makeApplication enter")
            val application = try {
                loadedApkClass.getMethod(
                    "makeApplication",
                    Boolean::class.javaPrimitiveType,
                    Instrumentation::class.java
                ).invoke(loadedApk, false, null) as? Application
            } catch (e: NoSuchMethodException) {
                loadedApkClass.getMethod(
                    "makeApplicationInner",
                    Boolean::class.javaPrimitiveType,
                    Instrumentation::class.java,
                    Boolean::class.javaPrimitiveType
                ).invoke(loadedApk, false, null, false) as? Application
            }
            if (application == null) {
                GuestBreadcrumb.log("framework makeApplication returned null")
                restoreInstrumentation(prevInstr)
                return null
            }
            GuestBreadcrumb.log("framework makeApplication exit app=" +
                application.javaClass.name)

            val record = ApplicationRecord(
                instanceId = instanceId,
                packageName = packageName,
                application = application,
                classLoader = guestClassLoader,
                applicationClassName = application.javaClass.name
            )
            applications[instanceId] = record

            if (virtualContext is com.nextvm.core.sandbox.VirtualContext) {
                virtualContext.setGuestApplication(application)
            }
            record.state = ApplicationState.ATTACHED

            if (providerNames.isNotEmpty()) {
                initContentProviders(
                    instanceId = instanceId,
                    providers = providerNames,
                    authorities = providerAuthorities,
                    classLoader = guestClassLoader,
                    virtualContext = appContext,
                    application = application,
                    providerMetaData = providerMetaData
                )
                record.state = ApplicationState.PROVIDERS_INSTALLED
            }

            callApplicationOnCreate(application)
            record.state = ApplicationState.RUNNING
            Timber.tag(TAG).i(
                "Framework LoadedApk bind complete for $packageName " +
                    "(app=${application.javaClass.name}, base=${application.baseContext?.javaClass?.simpleName})"
            )
            restoreInstrumentation(prevInstr)
            application
        } catch (e: Exception) {
            restoreInstrumentation(prevInstr)
            GuestBreadcrumb.logThrowable("framework bind FAILED", e)
            Timber.tag(TAG).w(e, "Framework LoadedApk bind failed for $packageName, falling back to legacy bind")
            applications.remove(instanceId)
            null
        }
    }

    /**
     * Create an Application instance using the guest app's ClassLoader.
     *
     * Mirrors the logic in:
     *   ActivityThread.java → LoadedApk.makeApplicationInner()
     *   AppComponentFactory.instantiateApplication() (Android 9+)
     */
    fun createApplication(
        instanceId: String,
        packageName: String,
        applicationClassName: String?,
        classLoader: ClassLoader,
        virtualContext: Context,
        appInfo: ApplicationInfo? = null
    ): Application? {
        val className = applicationClassName ?: "android.app.Application"

        Timber.tag(TAG).d("Creating Application: $className for $packageName")

        return try {
            // Try AppComponentFactory on Android 9+
            if (AndroidCompat.isAtLeastP) {
                val factoryApp = createViaAppComponentFactory(className, classLoader)
                if (factoryApp != null) {
                    Timber.tag(TAG).d("Application created via AppComponentFactory")
                    return factoryApp
                }
            }

            // Standard reflection path
            val appClass = if (className == "android.app.Application") {
                Application::class.java
            } else {
                classLoader.loadClass(className)
            }

            val app = appClass.getDeclaredConstructor().let { ctor ->
                ctor.isAccessible = true
                ctor.newInstance()
            } as Application

            Timber.tag(TAG).d("Application created via reflection: $className")
            app

        } catch (e: ClassNotFoundException) {
            Timber.tag(TAG).w("Application class not found: $className, falling back to base Application")
            try {
                Application::class.java.getDeclaredConstructor().newInstance()
            } catch (e2: Exception) {
                Timber.tag(TAG).e(e2, "Failed to create fallback Application")
                null
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to create Application: $className")
            null
        }
    }

    /**
     * Try to create Application via AppComponentFactory (Android 9+).
     *
     * Real Android uses AppComponentFactory to allow apps to customize
     * instantiation of Application, Activity, Service, etc.
     */
    private fun createViaAppComponentFactory(
        className: String,
        classLoader: ClassLoader
    ): Application? {
        return runSafe(TAG) {
            val factoryClass = Class.forName("android.app.AppComponentFactory")
            val factory = factoryClass.getDeclaredConstructor().newInstance()

            val instantiateMethod = findMethod(
                factoryClass,
                "instantiateApplication",
                arrayOf(ClassLoader::class.java, String::class.java)
            )
            instantiateMethod?.isAccessible = true
            instantiateMethod?.invoke(factory, classLoader, className) as? Application
        }
    }

    /**
     * Attach base context to Application.
     *
     * This calls Application.attach(context), which internally calls:
     *   - ContextWrapper.attachBaseContext(context)
     *   - Application.attachBaseContext(context) [overridable by app]
     *
     * We use the hidden Application.attach() method rather than just
     * attachBaseContext() because attach() also sets up internal fields
     * like mLoadedApk.
     */
    private fun attachBaseContext(application: Application, virtualContext: Context) {
        // CRITICAL: Before Application.attach(), inject guest app paths into the
        // LoadedApk that the ContextImpl holds. Application.attach() does:
        //   mLoadedApk = ContextImpl.getImpl(context).mPackageInfo
        // If we don't patch this, the LoadedApk has HOST paths (nativeLibraryDir etc.),
        // and when the guest app's attachBaseContext() calls System.load(), the runtime
        // looks up nativeLibraryDir from the LoadedApk's ApplicationInfo and fails.
        injectGuestPathsIntoLoadedApk(virtualContext)

        // FIX 1: Disable CheckJNI before guest Application.attach().
        // Jiagu/360-protected apps use reflection to call Runtime.load0(Class, String)
        // directly. In the virtual environment, the 'Class caller' argument becomes null
        // because the call originates from code loaded via custom ClassLoader/reflection.
        // CheckJNI catches the null caller's protection domains array (jarray == NULL)
        // in GetObjectArrayElement and triggers SIGABRT. Disabling CheckJNI prevents
        // this hard-abort — the null caller is harmless for actual library loading.
        disableCheckJniForGuest()

        // FIX 2: Patch Jiagu/packer stub Application fields before attach.
        // Packers like Jiagu store native lib extraction paths in static/instance String
        // fields. In the virtual environment these may be null, causing load failures.
        patchJiaguStubBeforeAttach(application, virtualContext)

        // FIX 3: Install Runtime.load0 caller fix to handle null caller class.
        installRuntimeLoadCallerFix(application, virtualContext)

        try {
            // Try the full attach() method first (mirrors real Android flow)
            val attachMethod = findMethod(
                Application::class.java,
                "attach",
                arrayOf(Context::class.java)
            )
            if (attachMethod != null) {
                attachMethod.isAccessible = true
                attachMethod.invoke(application, virtualContext)
                Timber.tag(TAG).d("Used Application.attach(context)")
                return
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Application.attach() failed, using attachBaseContext fallback")
        }

        // Fallback: directly call attachBaseContext via reflection
        try {
            val attachBaseMethod = findMethod(
                android.content.ContextWrapper::class.java,
                "attachBaseContext",
                arrayOf(Context::class.java)
            )
            attachBaseMethod?.isAccessible = true
            attachBaseMethod?.invoke(application, virtualContext)
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "attachBaseContext fallback also failed")
            // Last resort: set mBase field directly
            try {
                val mBaseField = findField(android.content.ContextWrapper::class.java, "mBase")
                mBaseField?.isAccessible = true
                mBaseField?.set(application, virtualContext)
                Timber.tag(TAG).d("Set mBase field directly as last resort")
            } catch (e2: Exception) {
                Timber.tag(TAG).e(e2, "All attach methods failed")
                throw RuntimeException("Cannot attach context to Application", e2)
            }
        }
    }

    /**
     * FIX 1: Disable CheckJNI in the current (guest) process.
     *
     * NOTE: VMRuntime.setCheckJni(boolean) does NOT exist on Android API 35+.
     * This method is kept as a best-effort attempt for older API levels.
     * The real fix for null-caller SIGABRT is the native Runtime.nativeLoad hook
     * installed by NativeHookBridge.hookRuntimeNativeLoad().
     */
    private fun disableCheckJniForGuest() {
        if (Build.VERSION.SDK_INT >= 35) {
            Timber.tag(TAG).d("Skipping disableCheckJniForGuest — VMRuntime.setCheckJni not available on API 35+")
            return
        }
        try {
            val vmRuntimeClass = Class.forName("dalvik.system.VMRuntime")
            val getRuntimeMethod = vmRuntimeClass.getDeclaredMethod("getRuntime")
            getRuntimeMethod.isAccessible = true
            val vmRuntime = getRuntimeMethod.invoke(null)

            val setCheckJniMethod = vmRuntimeClass.getDeclaredMethod(
                "setCheckJni", Boolean::class.javaPrimitiveType
            )
            setCheckJniMethod.isAccessible = true
            setCheckJniMethod.invoke(vmRuntime, false)
            Timber.tag(TAG).i("CheckJNI disabled for guest process")
        } catch (e: Exception) {
            Timber.tag(TAG).w("Failed to disable CheckJNI: ${e.message} (non-fatal — native hook handles this)")
        }
    }

    /**
     * FIX 2: Patch Jiagu/packer stub Application fields before attach.
     *
     * Packers like Jiagu (com.stub.StubApp) store native library extraction paths
     * and data directory paths in static/instance String fields. In the virtual
     * environment, these fields may be null because the packer's initialization
     * code hasn't run yet, or the paths it computed are wrong. This causes the
     * packer's attachBaseContext() to pass null/invalid paths to System.load().
     *
     * We scan the stub Application class for null String fields and set them to
     * the guest app's nativeLibraryDir, which is the most commonly needed path.
     */
    private fun patchJiaguStubBeforeAttach(application: Application, virtualContext: Context) {
        try {
            val appClass = application.javaClass
            val className = appClass.name

            // Only patch if it looks like a packer stub class
            if (!className.contains("stub", ignoreCase = true) &&
                !className.contains("jiagu", ignoreCase = true) &&
                !className.contains("wrapper", ignoreCase = true) &&
                !className.contains("Shell", ignoreCase = true) &&
                !className.contains("Qihoo", ignoreCase = true)
            ) {
                return
            }

            Timber.tag(TAG).d("Detected packer stub class: $className — patching fields")

            val nativeLibDir = virtualContext.applicationInfo?.nativeLibraryDir ?: return
            val dataDir = virtualContext.applicationInfo?.dataDir ?: return
            val sourceDir = virtualContext.applicationInfo?.sourceDir ?: return

            // Patch instance fields
            for (field in appClass.declaredFields) {
                try {
                    field.isAccessible = true
                    if (field.type == String::class.java) {
                        val value = field.get(application) as? String
                        if (value == null) {
                            // Null String field — likely a path that needs to be set
                            field.set(application, nativeLibDir)
                            Timber.tag(TAG).d("  Patched null field: ${field.name} → $nativeLibDir")
                        } else if (value.contains("/data/data/") &&
                            !value.contains("com.nextvm.app")
                        ) {
                            // Contains a real package data path — redirect to virtual sandbox
                            val redirected = value.replace(
                                Regex("/data/(data|user/0)/[^/]+"),
                                dataDir
                            )
                            if (redirected != value) {
                                field.set(application, redirected)
                                Timber.tag(TAG).d("  Redirected field: ${field.name} → $redirected")
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Skip inaccessible fields
                }
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "patchJiaguStubBeforeAttach failed (non-fatal)")
        }
    }

    /**
     * FIX 3: Install a caller-class fix for Runtime.load0 / Runtime.nativeLoad.
     *
     * When Jiagu calls Runtime.load0(Class<?> callerClass, String filename) via
     * reflection, callerClass can be null in the virtual environment. The ART runtime's
     * nativeLoad implementation uses the caller's ClassLoader to determine the linker
     * namespace, and a null caller causes CheckJNI to abort when accessing the caller's
     * protection domains array.
     *
     * This method:
     * 1. Sets Thread contextClassLoader to the guest's ClassLoader
     * 2. Ensures the guest Application class has a valid ProtectionDomain with
     *    CodeSource pointing to the guest APK path
     * 3. The actual JNI-level fix is in NativeHookBridge.hookRuntimeNativeLoad()
     */
    private fun installRuntimeLoadCallerFix(application: Application, virtualContext: Context) {
        try {
            // Ensure the current thread's contextClassLoader is the guest's ClassLoader.
            val guestClassLoader = application.javaClass.classLoader
            if (guestClassLoader != null) {
                Thread.currentThread().contextClassLoader = guestClassLoader
                Timber.tag(TAG).d("Set thread contextClassLoader to guest ClassLoader: ${guestClassLoader.javaClass.name}")
            }

            // Ensure the guest's Application class has a valid ProtectionDomain
            // with a CodeSource pointing to the guest APK. This prevents NPE/SIGABRT
            // when ART/CheckJNI tries to access the caller's ProtectionDomain array.
            try {
                val pd = application.javaClass.protectionDomain
                if (pd == null || pd.codeSource == null) {
                    // Inject a valid ProtectionDomain with CodeSource pointing to APK
                    val apkPath = virtualContext.applicationInfo?.sourceDir
                    if (apkPath != null) {
                        val codeSource = java.security.CodeSource(
                            java.io.File(apkPath).toURI().toURL(),
                            arrayOfNulls<java.security.cert.Certificate>(0)
                        )
                        val newPd = java.security.ProtectionDomain(codeSource, null)
                        // Set via reflection on the Class object
                        val pdField = findField(Class::class.java, "protectionDomain")
                            ?: findField(Class::class.java, "pd")
                        if (pdField != null) {
                            pdField.isAccessible = true
                            pdField.set(application.javaClass, newPd)
                            Timber.tag(TAG).d("Injected ProtectionDomain with CodeSource: $apkPath")
                        }
                    }
                } else {
                    Timber.tag(TAG).d("Guest Application ProtectionDomain already valid: $pd")
                }
            } catch (e: Exception) {
                Timber.tag(TAG).d("ProtectionDomain fix: ${e.message} (non-fatal)")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "installRuntimeLoadCallerFix failed (non-fatal)")
        }
    }

    /**
     * Inject guest app paths into the LoadedApk's ApplicationInfo.
     *
     * When Application.attach(context) is called, it sets:
     *   mLoadedApk = ContextImpl.getImpl(context).mPackageInfo
     *
     * Since VirtualContext wraps the HOST ContextImpl, mPackageInfo is the HOST's
     * LoadedApk with HOST paths. We patch its mApplicationInfo to have guest paths
     * so that Runtime.nativeLoad() and other framework code finds the right
     * nativeLibraryDir, sourceDir, and dataDir.
     */
    private fun injectGuestPathsIntoLoadedApk(virtualContext: Context) {
        try {
            // Walk the ContextWrapper chain to find the underlying ContextImpl
            var ctx: Context = virtualContext
            while (ctx is android.content.ContextWrapper) {
                val base = ctx.baseContext ?: break
                ctx = base
            }

            // Get mPackageInfo (LoadedApk) from ContextImpl
            val mPackageInfoField = findField(ctx::class.java, "mPackageInfo")
            mPackageInfoField?.isAccessible = true
            val loadedApk = mPackageInfoField?.get(ctx) ?: run {
                Timber.tag(TAG).w("Could not find mPackageInfo on ContextImpl")
                return
            }

            // Get mApplicationInfo from LoadedApk
            val appInfoField = findField(loadedApk::class.java, "mApplicationInfo")
            appInfoField?.isAccessible = true
            val loadedApkAppInfo = appInfoField?.get(loadedApk) as? ApplicationInfo ?: run {
                Timber.tag(TAG).w("Could not find mApplicationInfo on LoadedApk")
                return
            }

            // Read guest paths from VirtualContext.getApplicationInfo()
            val guestAppInfo = virtualContext.applicationInfo

            // Patch the LoadedApk's ApplicationInfo with guest paths
            loadedApkAppInfo.nativeLibraryDir = guestAppInfo.nativeLibraryDir
            loadedApkAppInfo.sourceDir = guestAppInfo.sourceDir
            loadedApkAppInfo.publicSourceDir = guestAppInfo.sourceDir
            loadedApkAppInfo.dataDir = guestAppInfo.dataDir

            // CRITICAL: Also patch LoadedApk.mLibDir which is used by
            // Runtime.nativeLoad() to construct the library search path.
            // Without this, the linker namespace has wrong paths and .so loading fails.
            val mLibDirField = findField(loadedApk::class.java, "mLibDir")
            if (mLibDirField != null) {
                mLibDirField.isAccessible = true
                mLibDirField.set(loadedApk, guestAppInfo.nativeLibraryDir)
                Timber.tag(TAG).d("Injected mLibDir into LoadedApk: ${guestAppInfo.nativeLibraryDir}")
            }

            Timber.tag(TAG).d(
                "Injected guest paths into LoadedApk: nativeLibDir=${loadedApkAppInfo.nativeLibraryDir}"
            )
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Failed to inject guest paths into LoadedApk (non-fatal)")
        }
    }

    /**
     * Patch LoadedApk.mApplication to point to the guest Application.
     *
     * Without this, ContextImpl.getApplicationContext() returns the HOST Application
     * (set when the process started). Framework code that calls getApplicationContext()
     * directly on ContextImpl (bypassing our ContextWrapper) would get NextVmApplication
     * instead of the guest Application — causing Hilt/Dagger cast failures and GMS
     * identity mismatches.
     */
    private fun patchLoadedApkApplication(virtualContext: Context, guestApplication: Application) {
        try {
            // Walk the ContextWrapper chain to find the underlying ContextImpl
            var ctx: Context = virtualContext
            while (ctx is android.content.ContextWrapper) {
                val base = ctx.baseContext ?: break
                ctx = base
            }

            // Get mPackageInfo (LoadedApk) from ContextImpl
            val mPackageInfoField = findField(ctx::class.java, "mPackageInfo")
            mPackageInfoField?.isAccessible = true
            val loadedApk = mPackageInfoField?.get(ctx) ?: run {
                Timber.tag(TAG).w("Could not find mPackageInfo for mApplication patch")
                return
            }

            // Patch LoadedApk.mApplication
            val mApplicationField = findField(loadedApk::class.java, "mApplication")
            if (mApplicationField != null) {
                mApplicationField.isAccessible = true
                mApplicationField.set(loadedApk, guestApplication)
                Timber.tag(TAG).d("Patched LoadedApk.mApplication to guest Application")
            } else {
                Timber.tag(TAG).w("Could not find mApplication field on LoadedApk")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Failed to patch LoadedApk.mApplication (non-fatal)")
        }
    }

    /**
     * Initialize ContentProviders before Application.onCreate().
     *
     * This mirrors ActivityThread.installContentProviders() which is called
     * BEFORE Instrumentation.callApplicationOnCreate().
     *
     * Critical providers that depend on this ordering:
     * - androidx.startup.InitializationProvider (AndroidX Startup)
     * - androidx.work.impl.WorkManagerInitializer (WorkManager)
     * - com.google.firebase.provider.FirebaseInitProvider (Firebase)
     * - androidx.lifecycle.ProcessLifecycleOwnerInitializer (Lifecycle)
     */
    fun initContentProviders(
        instanceId: String,
        providers: List<String>,
        authorities: Map<String, String>,
        classLoader: ClassLoader,
        virtualContext: Context,
        application: Application,
        providerMetaData: Map<String, Bundle> = emptyMap()
    ) {
        Timber.tag(TAG).d("Installing ${providers.size} ContentProviders for $instanceId")
        GuestBreadcrumb.log("providers begin n=" + providers.size +
            " list=" + providers.joinToString(","))

        val record = applications[instanceId]

        for (providerClassName in providers) {
            // Skip ShizukuProvider — requires INTERACT_ACROSS_USERS_FULL which
            // is not available in the virtual environment. Attempting to install
            // it causes SecurityException in ContentResolver.call().
            val providerAuthority = authorities[providerClassName] ?: ""
            if (providerClassName.contains("shizuku", ignoreCase = true) ||
                providerClassName.contains("rikka.shizuku", ignoreCase = true) ||
                providerAuthority.contains("shizuku", ignoreCase = true)
            ) {
                Timber.tag(TAG).d("Skipping ShizukuProvider: $providerClassName — cross-user permission unavailable")
                continue
            }

            GuestBreadcrumb.log("provider attachInfo enter $providerClassName")
            try {
                val providerClass = classLoader.loadClass(providerClassName)
                val provider = providerClass.getDeclaredConstructor().let { ctor ->
                    ctor.isAccessible = true
                    ctor.newInstance()
                } as ContentProvider

                // Build ProviderInfo for attachInfo()
                val providerInfo = ProviderInfo().apply {
                    name = providerClassName
                    authority = providerAuthority.ifEmpty {
                        "${virtualContext.packageName}.${providerClassName.substringAfterLast(".")}"
                    }
                    applicationInfo = virtualContext.applicationInfo
                    exported = false
                    enabled = true
                    grantUriPermissions = true
                    // v39: manifest meta-data parsed from the guest APK.
                    // Providers reading their meta-data in attachInfo /
                    // onCreate must find it here, as on a real install.
                    metaData = providerMetaData[providerClassName]
                }

                // Call ContentProvider.attachInfo(context, info)
                // This calls both attachInfo internally and then onCreate()
                // v39: pass the guest Application, as AOSP's
                // installContentProviders does — NOT a bare ContextImpl.
                // Providers that cast getContext() to Application (e.g.
                // SoulPermission's InitProvider, which registers the
                // activity-lifecycle tracker behind getTopActivity())
                // died on the cast, silently disabling themselves.
                provider.attachInfo(application, providerInfo)

                record?.contentProviders?.add(provider)
                Timber.tag(TAG).d("  Provider installed: $providerClassName")
                GuestBreadcrumb.log("provider ok $providerClassName")

            } catch (e: ClassNotFoundException) {
                GuestBreadcrumb.logThrowable(
                    "provider NOT FOUND, skipped: $providerClassName", e)
                Timber.tag(TAG).w("ContentProvider class not found: $providerClassName (skipping)")
            } catch (e: SecurityException) {
                GuestBreadcrumb.logThrowable(
                    "provider SecurityException SWALLOWED, skipped: $providerClassName", e)
                Timber.tag(TAG).w("SecurityException skipping provider $providerClassName: ${e.message}")
            } catch (e: IllegalStateException) {
                GuestBreadcrumb.logThrowable(
                    "provider IllegalStateException SWALLOWED, skipped: $providerClassName", e)
                Timber.tag(TAG).w("IllegalStateException skipping provider $providerClassName: ${e.message}")
            } catch (e: Exception) {
                GuestBreadcrumb.logThrowable(
                    "provider FAILED (bind continues): $providerClassName", e)
                Timber.tag(TAG).e(e, "Failed to install ContentProvider: $providerClassName")
                // Don't fail the whole app — some providers are optional
            }
        }
    }

    /**
     * Call Application.onCreate() using Instrumentation pattern.
     *
     * Mirrors:
     *   Instrumentation.callApplicationOnCreate(app) in ActivityThread.handleBindApplication()
     */
    private fun callApplicationOnCreate(application: Application) {
        GuestBreadcrumb.log("Application.onCreate enter " + application.javaClass.name)
        try {
            // Use Instrumentation if available (more accurate mirroring)
            val instrumentation = Instrumentation()
            instrumentation.callApplicationOnCreate(application)
            Timber.tag(TAG).d("Application.onCreate() called via Instrumentation")
            GuestBreadcrumb.log("Application.onCreate exit ok")
        } catch (e: RuntimeException) {
            // Check if this is a ShizukuProvider SecurityException — swallow it.
            // ZArchiver calls ShizukuProvider.a() in onCreate() which triggers
            // ContentResolver.call() to rikka.shizuku.ShizukuProvider. The system
            // throws SecurityException because INTERACT_ACROSS_USERS_FULL is missing.
            // ZArchiver can run without Shizuku root access.
            val cause = e.cause?.cause ?: e.cause ?: e
            if (cause is SecurityException &&
                (cause.message?.contains("ShizukuProvider", ignoreCase = true) == true ||
                 cause.message?.contains("INTERACT_ACROSS_USERS", ignoreCase = true) == true ||
                 cause.message?.contains("shizuku", ignoreCase = true) == true)
            ) {
                GuestBreadcrumb.logThrowable(
                    "Application.onCreate SecurityException SWALLOWED (shizuku rule)", e)
                Timber.tag(TAG).w("Shizuku SecurityException in onCreate swallowed — continuing without Shizuku")
                return
            }
            // Not Shizuku-related — try direct call fallback
            Timber.tag(TAG).w(e, "Instrumentation.callApplicationOnCreate() failed, trying direct")
            try {
                application.onCreate()
            } catch (e2: RuntimeException) {
                val cause2 = e2.cause?.cause ?: e2.cause ?: e2
                if (cause2 is SecurityException &&
                    (cause2.message?.contains("ShizukuProvider", ignoreCase = true) == true ||
                     cause2.message?.contains("INTERACT_ACROSS_USERS", ignoreCase = true) == true ||
                     cause2.message?.contains("shizuku", ignoreCase = true) == true)
                ) {
                    GuestBreadcrumb.logThrowable(
                        "Application.onCreate (direct) SecurityException SWALLOWED (shizuku rule)", e2)
                    Timber.tag(TAG).w("Shizuku SecurityException in direct onCreate swallowed")
                    return
                }
                Timber.tag(TAG).e(e2, "Application.onCreate() direct call also failed")
                throw e2
            } catch (e2: Exception) {
                Timber.tag(TAG).e(e2, "Application.onCreate() direct call also failed")
                throw e2
            }
        } catch (e: Exception) {
            GuestBreadcrumb.logThrowable(
                "Application.onCreate via Instrumentation FAILED, calling directly", e)
            Timber.tag(TAG).w(e, "Instrumentation.callApplicationOnCreate() failed, calling directly")
            try {
                application.onCreate()
                GuestBreadcrumb.log("Application.onCreate exit ok (direct)")
            } catch (e2: Exception) {
                GuestBreadcrumb.logThrowable("Application.onCreate direct call FAILED", e2)
                Timber.tag(TAG).e(e2, "Application.onCreate() direct call also failed")
                throw e2
            }
        }
    }

    /**
     * Build an ApplicationInfo suitable for the guest app.
     */
    private fun buildApplicationInfo(
        packageName: String,
        apkPath: String,
        virtualContext: Context
    ): ApplicationInfo {
        return ApplicationInfo().apply {
            this.packageName = packageName
            this.sourceDir = apkPath
            this.publicSourceDir = apkPath
            this.dataDir = virtualContext.dataDir.absolutePath
            this.nativeLibraryDir = virtualContext.applicationInfo.nativeLibraryDir
            this.processName = packageName
            this.enabled = true
            this.flags = ApplicationInfo.FLAG_HAS_CODE or ApplicationInfo.FLAG_ALLOW_CLEAR_USER_DATA
            // longVersionCode defaults to 0 on new ApplicationInfo

            // Populate metaData from the guest APK so SDKs (AppLovin, Firebase,
            // Facebook, CronetProvider, etc.) can read their <meta-data> tags.
            // Also inject essential GMS meta-data if not already present.
            try {
                val pm = virtualContext.packageManager
                val pkgInfo = pm.getPackageArchiveInfo(
                    apkPath,
                    android.content.pm.PackageManager.GET_META_DATA
                )
                pkgInfo?.applicationInfo?.let { it2 ->
                    it2.sourceDir = apkPath
                    it2.publicSourceDir = apkPath
                }
                val bundle = pkgInfo?.applicationInfo?.metaData ?: android.os.Bundle()

                // Inject GMS version meta-data if the guest APK doesn't already have it.
                // Many SDKs (AppLovin, Firebase Analytics, CronetProvider) crash without this.
                if (!bundle.containsKey("com.google.android.gms.version")) {
                    bundle.putInt("com.google.android.gms.version", 243431006)
                }

                this.metaData = bundle
            } catch (e: Exception) {
                Timber.tag(TAG).w(e, "Failed to parse metaData from APK: $apkPath")
                // At minimum provide GMS version to avoid common SDK crashes
                this.metaData = android.os.Bundle().apply {
                    putInt("com.google.android.gms.version", 243431006)
                }
            }
        }
    }

    /**
     * Terminate a guest app's Application instance.
     * Calls Application.onTerminate() and cleans up all ContentProviders.
     */
    fun terminateApplication(instanceId: String) {
        val record = applications[instanceId] ?: run {
            Timber.tag(TAG).w("No Application record found for $instanceId")
            return
        }

        Timber.tag(TAG).i("Terminating application for ${record.packageName} ($instanceId)")

        try {
            // Shut down ContentProviders first
            for (provider in record.contentProviders) {
                try {
                    provider.shutdown()
                } catch (e: Exception) {
                    Timber.tag(TAG).w(e, "Error shutting down provider: ${provider.javaClass.name}")
                }
            }
            record.contentProviders.clear()

            // Call Application.onTerminate()
            try {
                record.application.onTerminate()
            } catch (e: Exception) {
                Timber.tag(TAG).w(e, "Application.onTerminate() threw exception")
            }

            record.state = ApplicationState.TERMINATED
            Timber.tag(TAG).i("Application terminated for ${record.packageName}")

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error terminating application for $instanceId")
        } finally {
            applications.remove(instanceId)
        }
    }

    /**
     * Propagate configuration change to a running Application.
     */
    fun onConfigurationChanged(instanceId: String, newConfig: Configuration) {
        val record = applications[instanceId] ?: return
        if (record.state != ApplicationState.RUNNING) return

        try {
            record.application.onConfigurationChanged(newConfig)
            Timber.tag(TAG).d("Configuration changed for ${record.packageName}")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error dispatching config change to ${record.packageName}")
        }
    }

    /**
     * Propagate low memory signal to a running Application.
     */
    fun onLowMemory(instanceId: String) {
        val record = applications[instanceId] ?: return
        if (record.state != ApplicationState.RUNNING) return

        try {
            record.application.onLowMemory()
            Timber.tag(TAG).d("onLowMemory dispatched to ${record.packageName}")
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Error dispatching onLowMemory")
        }
    }

    /**
     * Propagate trim memory signal to a running Application.
     */
    fun onTrimMemory(instanceId: String, level: Int) {
        val record = applications[instanceId] ?: return
        if (record.state != ApplicationState.RUNNING) return

        try {
            record.application.onTrimMemory(level)
            Timber.tag(TAG).d("onTrimMemory($level) dispatched to ${record.packageName}")
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Error dispatching onTrimMemory")
        }
    }

    // ---------- Query Methods ----------

    /** Get the Application instance for a guest app */
    fun getApplication(instanceId: String): Application? =
        applications[instanceId]?.application

    /** Get the ApplicationRecord for a guest app */
    fun getApplicationRecord(instanceId: String): ApplicationRecord? =
        applications[instanceId]

    /** Check if an application is bound and running */
    fun isApplicationRunning(instanceId: String): Boolean {
        val record = applications[instanceId] ?: return false
        return record.state == ApplicationState.RUNNING
    }

    /** Get all running application instance IDs */
    fun getRunningInstanceIds(): Set<String> {
        return applications.entries
            .filter { it.value.state == ApplicationState.RUNNING }
            .map { it.key }
            .toSet()
    }

    /** Get the number of running applications */
    fun getRunningCount(): Int =
        applications.values.count { it.state == ApplicationState.RUNNING }

    /** Terminate all running applications */
    fun terminateAll() {
        Timber.tag(TAG).i("Terminating all ${applications.size} applications")
        val instanceIds = applications.keys.toList()
        for (id in instanceIds) {
            terminateApplication(id)
        }
    }
}
