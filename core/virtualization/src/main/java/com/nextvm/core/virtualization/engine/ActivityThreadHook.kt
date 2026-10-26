package com.nextvm.core.virtualization.engine

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.os.Handler
import android.os.IBinder
import android.os.Message
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.common.runSafe
import com.nextvm.core.model.VirtualIntentExtras
import com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
import java.io.File
import com.nextvm.core.services.gms.GoogleAccountInfo
import timber.log.Timber

/**
 * ActivityThreadHook — The core mechanism that makes virtual apps work.
 *
 * Based on Android 16 frameworks/base analysis:
 * - ActivityThread.java line ~2403: H handler message codes
 * - EXECUTE_TRANSACTION = 159 (Android 9+): ALL activity lifecycle goes through this
 * - msg.obj = ClientTransaction containing LaunchActivityItem with mIntent + mInfo
 *
 * What this hook does:
 * 1. Intercepts ActivityThread's Handler (mH) via mCallback injection
 * 2. When Android tries to launch a stub Activity (EXECUTE_TRANSACTION),
 *    we extract the real target from the Intent extras
 * 3. We replace the ActivityInfo and Intent to load the guest app's class
 *    via our DexClassLoader instead of the stub class
 *
 * Hook chain:
 * System Server -> ApplicationThread.scheduleTransaction(ClientTransaction)
 *   -> sendMessage(H.EXECUTE_TRANSACTION = 159, transaction)
 *     -> [OUR HOOK INTERCEPTS HERE]
 *       -> Extract LaunchActivityItem from ClientTransaction
 *       -> Read _nextvm_target_activity from Intent extras
 *       -> Swap ActivityInfo.name to the real guest Activity class
 *       -> Replace ClassLoader with guest app's DexClassLoader
 *     -> Original mH.handleMessage() runs with modified transaction
 *       -> performLaunchActivity() uses our modified class name
 */
class ActivityThreadHook(
    private val context: Context,
    private val stubRegistry: StubRegistry,
    private val engine: VirtualEngine
) {
    /** The host app's package name, used for LoadedApk injection */
    internal val hostPackageName: String = context.packageName

    companion object {
        private const val TAG = "ATHook"

        /** Android 9+ EXECUTE_TRANSACTION message code */
        private const val EXECUTE_TRANSACTION = 159

        /** Legacy LAUNCH_ACTIVITY for Android < 9 */
        private const val LAUNCH_ACTIVITY = 100

        /** BIND_APPLICATION */
        private const val BIND_APPLICATION = 110

        /** CREATE_SERVICE */
        private const val CREATE_SERVICE = 114

        /** RECEIVER */
        private const val RECEIVER = 113
    }

    private var originalCallback: Handler.Callback? = null
    private var installed = false

    /**
     * Install the ActivityThread.mH hook.
     * This MUST be called after hidden API bypass.
     */
    fun install(): Boolean {
        if (installed) {
            Timber.tag(TAG).d("Already installed")
            return true
        }

        try {
            // 1. Get ActivityThread instance
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null)
                ?: run {
                    Timber.tag(TAG).e("ActivityThread.currentActivityThread() returned null")
                    return false
                }

            // 2. Get mH (the Handler)
            val mHField = findField(atClass, "mH")
                ?: run {
                    Timber.tag(TAG).e("Cannot find mH field in ActivityThread")
                    return false
                }
            mHField.isAccessible = true
            val mH = mHField.get(activityThread) as Handler

            // 3. Get mCallback field on Handler
            val callbackField = findField(Handler::class.java, "mCallback")
                ?: run {
                    Timber.tag(TAG).e("Cannot find mCallback field in Handler")
                    return false
                }
            callbackField.isAccessible = true

            // 4. Save original callback
            originalCallback = callbackField.get(mH) as? Handler.Callback

            // 5. Install our callback
            callbackField.set(mH, Handler.Callback { msg ->
                try {
                    handleMessage(msg)
                } catch (e: Exception) {
                    Timber.tag(TAG).e(e, "Error in hook callback for msg.what=${msg.what}")
                }
                // Return false to let the original handler also process the message
                // (with our modifications applied)
                originalCallback?.handleMessage(msg) ?: false
            })

            installed = true
            Timber.tag(TAG).i("ActivityThread.mH hook installed successfully")

            // Install crash-safe main looper wrapper to prevent GMS SecurityExceptions
            // from killing the virtual process. GMS dynamite modules (measurement, etc.)
            // post Handler messages that can throw SecurityException when the calling
            // package name doesn't match the host UID. Without this, the entire :p0
            // process crashes.
            installMainLooperCrashGuard()

            return true

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install ActivityThread.mH hook")
            return false
        }
    }

    private fun installMainLooperCrashGuard() {
        try {
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                while (true) {
                    try {
                        android.os.Looper.loop()
                    } catch (e: Throwable) {
                        // Walk the cause chain to find the root exception
                        var root: Throwable = e
                        while (root.cause != null) root = root.cause!!

                        // Only consume the narrowly identified system-identity failures
                        // caused by virtualized GMS calls. Guest resource failures must
                        // remain fatal so missing resource injection is observable;
                        // compatibility belongs in the guest Resources instance.
                        if (root is SecurityException &&
                            (root.message?.contains("Unknown calling package name") == true ||
                             root.message?.contains("does not belong to") == true)) {
                            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                                .logThrowable(
                                    "main-looper guard SUPPRESSED exception (message consumed)", e)
                            Timber.tag(TAG).w(e, "Suppressed GMS SecurityException in main looper: ${root.message}")
                            // Continue looping — the crashed message is consumed
                        } else {
                            // Re-throw non-GMS exceptions to preserve normal crash behavior
                            throw e
                        }
                    }
                }
            }
            Timber.tag(TAG).i("Main looper crash guard installed")
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Failed to install main looper crash guard")
        }
    }

    /**
     * Install the Instrumentation hook early, synchronously.
     * This MUST be called right after install() so that newActivity()
     * is intercepted from the very first EXECUTE_TRANSACTION.
     */
    fun installInstrumentationHookEarly() {
        hookInstrumentationIfNeeded()
    }

    /**
     * Process a Handler message from ActivityThread.mH.
     * This is called for EVERY lifecycle event in the app process.
     */
    private fun handleMessage(msg: Message): Boolean {
        return when (msg.what) {
            EXECUTE_TRANSACTION -> handleExecuteTransaction(msg)
            LAUNCH_ACTIVITY -> handleLegacyLaunchActivity(msg) // Pre-Android 9
            CREATE_SERVICE -> handleCreateService(msg)
            RECEIVER -> handleReceiver(msg)
            else -> false
        }
    }

    /**
     * Handle EXECUTE_TRANSACTION (159) — Android 9+.
     * The ClientTransaction contains LaunchActivityItem and lifecycle items.
     *
     * From Android 16 analysis:
     * - ClientTransaction has getCallbacks() returning List<ClientTransactionItem>
     * - LaunchActivityItem has mIntent (Intent) and mInfo (ActivityInfo)
     * - We modify both to point to the guest app's real Activity
     */
    private fun handleExecuteTransaction(msg: Message): Boolean {
        val transaction = msg.obj ?: return false

        try {
            val transactionClass = Class.forName("android.app.servertransaction.ClientTransaction")

            // FIX 2: Extract activity token from ClientTransaction (correct process context).
            // ClientTransaction.mActivityToken is the canonical token that ActivityThread
            // uses to register in mActivities. Using this instead of
            // LaunchActivityItem.mActivityToken avoids cross-process BinderProxy
            // token mismatch issues.
            val ctTokenField = findField(transactionClass, "mActivityToken")
            ctTokenField?.isAccessible = true
            val transactionToken = ctTokenField?.get(transaction) as? IBinder

            val getCallbacks = transactionClass.getDeclaredMethod("getCallbacks")
            getCallbacks.isAccessible = true

            @Suppress("UNCHECKED_CAST")
            val callbacks = getCallbacks.invoke(transaction) as? List<Any> ?: return false

            // v76: delivery witness. Record every activity-related
            // transaction item AMS delivers INTO this process, with
            // wall-clock time (same clock as logcat and the
            // binderwrap trace). launch99's rewritten AppTab start
            // produced no second activity and no log of any delivery;
            // this separates "AMS never delivered anything" from
            // "AMS delivered (e.g. a NewIntentItem onto the existing
            // record) and the guest side dropped it".
            try {
                val lifecycleReq = try {
                    val m = transactionClass.getDeclaredMethod(
                        "getLifecycleStateRequest"
                    )
                    m.isAccessible = true
                    m.invoke(transaction)
                } catch (_: Throwable) {
                    null
                }
                if (lifecycleReq != null) {
                    val ln = lifecycleReq::class.java.name
                    if (ln.contains("ActivityItem")) {
                        traceDelivery("lifecycle-request " + ln.substringAfterLast('.'))
                    }
                }
            } catch (_: Throwable) {
                // witness only; never disturb delivery
            }

            for (callback in callbacks) {
                val callbackClassName = callback::class.java.name

                if (callbackClassName.contains("ActivityItem") ||
                    callbackClassName.contains("NewIntentItem")
                ) {
                    traceDelivery(describeTransactionItem(callback, callbackClassName))
                }

                if (callbackClassName.contains("LaunchActivityItem")) {
                    return handleLaunchActivityItem(callback, transactionToken)
                }

                // Intercept ActivityResultItem to catch Google Sign-In results
                if (callbackClassName.contains("ActivityResultItem")) {
                    handleActivityResultItem(callback)
                    // Return false so the original handler still processes the result normally
                }
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error handling EXECUTE_TRANSACTION")
        }

        return false
    }

    private val deliveryTraceLock = Any()

    /** v76: append one delivery-witness line to the shared trace file. */
    private fun traceDelivery(line: String) {
        try {
            val f = java.io.File(
                context.filesDir,
                "startactivity-trace-" + android.os.Process.myPid() + ".log"
            )
            synchronized(deliveryTraceLock) {
                f.appendText(
                    "[t=" + System.currentTimeMillis() + "] " +
                        "athook-delivery: " + line + "\n"
                )
            }
        } catch (_: Throwable) {
            // witness only; never disturb delivery
        }
    }

    /** v76: one-line description of a transaction item for the witness. */
    private fun describeTransactionItem(item: Any, className: String): String {
        val simple = className.substringAfterLast('.')
        return try {
            when {
                className.contains("LaunchActivityItem") -> {
                    val intentField = findField(item::class.java, "mIntent")
                    intentField?.isAccessible = true
                    val intent = intentField?.get(item) as? Intent
                    simple + " cmp=" + intent?.component +
                        " nextvmExtras=" +
                        (intent?.getStringExtra(
                            VirtualIntentExtras.TARGET_PACKAGE
                        ) != null) +
                        " target=" + intent?.getStringExtra(
                            VirtualIntentExtras.TARGET_ACTIVITY
                        )
                }
                className.contains("NewIntentItem") -> {
                    val intentsField = findField(item::class.java, "mIntents")
                    intentsField?.isAccessible = true
                    @Suppress("UNCHECKED_CAST")
                    val intents = intentsField?.get(item) as? List<Intent>
                    simple + " intents=[" +
                        (intents?.joinToString(",") {
                            it.component?.flattenToShortString() ?: "?"
                        } ?: "?") + "]"
                }
                else -> simple
            }
        } catch (_: Throwable) {
            simple + " <describe failed>"
        }
    }

    /**
     * Handle ActivityResultItem — intercept activity results from GMS Sign-In.
     *
     * When a guest app starts Google Sign-In, GMS returns the result via
     * onActivityResult(). In Android 9+, this is delivered as an ActivityResultItem
     * inside a ClientTransaction. We intercept this to:
     * 1. Detect Google Sign-In results (by checking the data Intent)
     * 2. Call googleSignInManager.handleSignInResult() to store the account
     * 3. Let the original handler proceed (guest app's onActivityResult runs normally)
     */
    private fun handleActivityResultItem(item: Any) {
        try {
            val itemClass = item::class.java

            // ActivityResultItem has: mResultCode (int), mData (Intent)
            val resultCodeField = findField(itemClass, "mResultCode")
            resultCodeField?.isAccessible = true
            val resultCode = resultCodeField?.get(item) as? Int ?: return

            val dataField = findField(itemClass, "mResultData")
                ?: findField(itemClass, "mData")
            dataField?.isAccessible = true
            val data = dataField?.get(item) as? Intent ?: return

            // Check if this is a Google Sign-In result (marked by our intercept layer)
            if (!data.getBooleanExtra("_nextvm_is_virtual_sign_in", false) &&
                !isGmsSignInResultIntent(data)) {
                return
            }

            if (resultCode != android.app.Activity.RESULT_OK) {
                Timber.tag(TAG).d("Google Sign-In result: CANCELED or FAILED ($resultCode)")
                return
            }

            // Find the instanceId from the result intent extras
            val instanceId = data.getStringExtra("_nextvm_instance_id")
                ?: findRunningInstanceId()
                ?: return

            // Route to the GMS manager to store the signed-in account
            val gmsManager = engine.getGmsManager()
            val signedInAccount = gmsManager.googleSignInManager.handleSignInResult(instanceId, data)
            if (signedInAccount != null) {
                // Store the account in VirtualAccountManager
                gmsManager.setGoogleAccount(instanceId, GoogleAccountInfo(
                    email = signedInAccount.email,
                    displayName = signedInAccount.displayName ?: "",
                    photoUrl = signedInAccount.photoUrl ?: "",
                    authToken = signedInAccount.idToken ?: "",
                    idToken = signedInAccount.idToken ?: ""
                ))
                Timber.tag(TAG).i("Google Sign-In result processed for $instanceId: ${signedInAccount.email}")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).d("ActivityResultItem inspection error: ${e.message}")
        }
    }

    /**
     * Check if an Intent looks like a Google Sign-In result from real GMS.
     * Detects results from GoogleSignInActivity or AccountManager account picker.
     */
    private fun isGmsSignInResultIntent(intent: Intent): Boolean {
        val component = intent.component ?: return false
        return component.packageName == "com.google.android.gms" ||
                component.className.contains("SignIn", ignoreCase = true) ||
                intent.hasExtra("googleSignInAccount") ||
                intent.hasExtra("googleSignInStatus") ||
                (intent.getStringExtra(android.accounts.AccountManager.KEY_ACCOUNT_NAME) != null &&
                 intent.getStringExtra(android.accounts.AccountManager.KEY_ACCOUNT_TYPE) == "com.google")
    }

    /**
     * Find the instanceId of the currently active virtual app.
     * Used as fallback when the Sign-In result doesn't carry _nextvm_instance_id.
     */
    private fun findRunningInstanceId(): String? {
        return try {
            engine.getRunningApps().keys.firstOrNull()
        } catch (_: Exception) { null }
    }

    /**
     * Process a LaunchActivityItem — the critical class swap point.
     *
     * Android 16 LaunchActivityItem fields (from our analysis):
     * - mIntent: Intent — the launch intent we put extras into
     * - mInfo: ActivityInfo — activity metadata, contains className
     * - mActivityToken: IBinder — the activity's identity token
     *
     * Post-swap injection chain:
     * 1. Swap ActivityInfo.name + applicationInfo to guest app
     * 2. Replace ClassLoader via LoadedApk so performLaunchActivity() uses DexClassLoader
     * 3. Mark resources for post-create injection (resources/theme applied in Instrumentation)
     * 4. Register pending context replacement (VirtualContext wrapping)
     */
    private fun handleLaunchActivityItem(item: Any, transactionToken: IBinder? = null): Boolean {
        try {
            val itemClass = item::class.java

            // Get mIntent
            val intentField = findField(itemClass, "mIntent")
            intentField?.isAccessible = true
            val intent = intentField?.get(item) as? Intent ?: return false

            // Check if this is a NEXTVM stub launch
            val targetPackage = intent.getStringExtra(VirtualIntentExtras.TARGET_PACKAGE)
                ?: return false
            val rawTargetActivity = intent.getStringExtra(VirtualIntentExtras.TARGET_ACTIVITY)
                ?: return false
            val instanceId = intent.getStringExtra(VirtualIntentExtras.INSTANCE_ID)
                ?: return false
            val apkPath = intent.getStringExtra(VirtualIntentExtras.APK_PATH)
                ?: return false
            val processSlot = intent.getIntExtra("_nextvm_process_slot", 0)

            // Resolve activity-aliases: if the target is an alias (no real class),
            // use the targetActivity (the real class it points to)
            val targetActivity = engine.resolveActivityAlias(targetPackage, rawTargetActivity)
            if (targetActivity != rawTargetActivity) {
                Timber.tag(TAG).i("Resolved activity alias: $rawTargetActivity → $targetActivity")
            }

            Timber.tag(TAG).i("Intercepted stub launch → swapping to $targetActivity ($targetPackage)")

            // === RACE CONDITION FIX: Wait for engine init if not ready ===
            // Engine init runs on background thread, but launch intercept happens on main thread.
            // We must ensure the engine is fully initialized before proceeding with class swap.
            val engineStatus = engine.getEngineStatus()
            if (engineStatus != com.nextvm.core.model.EngineStatus.READY) {
                Timber.tag(TAG).w("Engine not ready ($engineStatus) — waiting (max 10s)...")
                val waitStart = System.currentTimeMillis()
                while (engine.getEngineStatus() != com.nextvm.core.model.EngineStatus.READY) {
                    if (System.currentTimeMillis() - waitStart > 10_000) {
                        Timber.tag(TAG).e("Engine init timed out during launch intercept!")
                        break
                    }
                    Thread.sleep(50)
                }
                Timber.tag(TAG).i("Engine ready, proceeding with class swap")
            }

            // Get mInfo (ActivityInfo)
            val infoField = findField(itemClass, "mInfo")
            infoField?.isAccessible = true
            val activityInfo = infoField?.get(item) ?: return false

            // === STEP 0: Pre-register the activity token in mActivities ===
            // TransactionExecutor calls getActivityClient(token) BEFORE our hook
            // can finish. If the token is absent from ActivityThread.mActivities,
            // the framework crashes with "Target activity: Not found for token".
            // We pre-register a blank ActivityClientRecord now so the lookup succeeds.
            //
            // FIX 2: Prefer token from ClientTransaction (passed by handleExecuteTransaction)
            // which is in the correct process context, instead of LaunchActivityItem.mActivityToken
            // which can be a cross-process BinderProxy.
            val token = transactionToken ?: run {
                val tokenField = findField(itemClass, "mActivityToken")
                tokenField?.isAccessible = true
                tokenField?.get(item) as? IBinder
            }
            if (token != null) {
                preRegisterActivityToken(token, activityInfo as ActivityInfo, intent)
            } else {
                Timber.tag(TAG).w("Activity token not found (neither ClientTransaction nor LaunchActivityItem) — skipped")
            }

            // === STEP 1: Swap the Activity class name ===
            val aiClass = activityInfo::class.java

            // Set ActivityInfo.name to the real guest Activity class
            val nameField = findField(aiClass, "name")
            nameField?.isAccessible = true
            nameField?.set(activityInfo, targetActivity)

            // Set ActivityInfo.packageName
            val aiPkgField = findField(aiClass, "packageName")
            aiPkgField?.isAccessible = true
            aiPkgField?.set(activityInfo, targetPackage)

            // Set ActivityInfo.applicationInfo to guest app info
            val appInfoField = findField(aiClass, "applicationInfo")
            appInfoField?.isAccessible = true
            val appInfo = appInfoField?.get(activityInfo)
            if (appInfo != null) {
                val pkgNameField = findField(appInfo::class.java, "packageName")
                pkgNameField?.isAccessible = true
                pkgNameField?.set(appInfo, targetPackage)

                // Set APK path so the ClassLoader finds the right classes
                val sourceDirField = findField(appInfo::class.java, "sourceDir")
                sourceDirField?.isAccessible = true
                sourceDirField?.set(appInfo, apkPath)

                val publicSourceDirField = findField(appInfo::class.java, "publicSourceDir")
                publicSourceDirField?.isAccessible = true
                publicSourceDirField?.set(appInfo, apkPath)

                // Set nativeLibraryDir for native code loading
                val nativeLibDir = engine.getNativeLibDir(instanceId)
                if (nativeLibDir != null) {
                    val nlField = findField(appInfo::class.java, "nativeLibraryDir")
                    nlField?.isAccessible = true
                    nlField?.set(appInfo, nativeLibDir)
                }

                // Set dataDir to sandbox path
                val dataDir = engine.getDataDir(instanceId)
                if (dataDir != null) {
                    val ddField = findField(appInfo::class.java, "dataDir")
                    ddField?.isAccessible = true
                    ddField?.set(appInfo, dataDir)
                }
            }

            // Modify the Intent's component to point to the real Activity
            intent.component = ComponentName(targetPackage, targetActivity)

            // === STEP 1.5 (v52): Begin the breadcrumb witness BEFORE
            // the LoadedApk surgery below, and attach its file right
            // away. The guest files dir is known from the instance data
            // dir, so the log reaches disk even if this guest process
            // dies seconds later. Previously the file was attached only
            // on bind success (and the session itself was unicom-only),
            // leaving failed binds of other guests with no witness.
            runSafe(TAG) {
                GuestBreadcrumb.begin(targetPackage)
                val dataDir = engine.getDataDir(instanceId)
                if (dataDir != null) {
                    GuestBreadcrumb.attachFile(File(dataDir, "files"))
                }
            }

            // === STEP 2: Replace ClassLoader in LoadedApk ===
            replaceClassLoader(targetPackage, instanceId, apkPath)

            // === STEP 2.1 (v79 probe): inspect the resource state of
            // the clone AOSP is about to consume for this launch ===
            probeLaunchResources(targetPackage, apkPath, targetActivity)

            // === STEP 2.2 (v80/v81): launch103 proved the guest APK
            // copy exists at StartPage time but is gone ~6s later
            // when AppTab launches; launch104's watcher caught the
            // unlink inside ZWRisk.setup() (agree flow, ~160ms
            // before the AppTab start). startApkWatchdog now also
            // restores the copy from its guard hard link. ===
            startApkWatchdog(instanceId, apkPath)

            // === STEP 2.5: Boot guest Application lifecycle (CRITICAL) ===
            // Most Android apps require Application.onCreate() to run before any
            // Activity is created. Firebase, Hilt, WorkManager, AndroidX Startup
            // all initialize via Application or ContentProvider.onCreate().
            // We must boot the Application BEFORE the Activity is instantiated.
            runSafe(TAG) {
                engine.ensureGuestApplicationBooted(instanceId, targetPackage, apkPath)
            }

            // === STEP 3: Register pending resource injection ===
            // Resources and theme are injected via Instrumentation.callActivityOnCreate()
            // or in the ActivityThread.performLaunchActivity() flow AFTER the Activity is
            // instantiated. We register the pending injection so the next created Activity
            // gets its resources replaced.
            registerPendingResourceInjection(instanceId, apkPath, targetPackage)

            // === STEP 4: Register pending VirtualContext wrapping ===
            // The VirtualContext is attached after Activity.attach() is called.
            // We track that this launch needs context replacement.
            registerPendingContextWrap(instanceId, targetPackage, processSlot)

            // === STEP 5: Register Instrumentation hook for post-create injection ===
            // Hook Instrumentation.callActivityOnCreate to inject resources + context
            // BEFORE the Activity's own onCreate() runs
            hookInstrumentationIfNeeded()

            Timber.tag(TAG).i("Class swap complete: $targetActivity (instance: $instanceId)")
            return false // Let the modified transaction proceed

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in LaunchActivityItem class swap")
            return false
        }
    }

    // ==================== Post-Swap Injection Helpers ====================

    /**
     * Pending resource injections: instanceId -> (apkPath, packageName)
     * Consumed after Activity is created.
     */
    private val pendingResourceInjections = mutableMapOf<String, Triple<String, String, String>>()

    /**
     * Pending context wraps: instanceId -> (packageName, processSlot)
     */
    private val pendingContextWraps = mutableMapOf<String, Pair<String, Int>>()

    private var instrumentationHooked = false

    private fun registerPendingResourceInjection(instanceId: String, apkPath: String, packageName: String) {
        pendingResourceInjections[instanceId] = Triple(instanceId, apkPath, packageName)
        // Also store in a "last launch" field so Instrumentation hook can find it
        lastLaunchInstanceId = instanceId
        lastLaunchApkPath = apkPath
        lastLaunchPackageName = packageName
        Timber.tag(TAG).d("Registered pending resource injection for $instanceId")
    }

    private fun registerPendingContextWrap(instanceId: String, packageName: String, processSlot: Int) {
        pendingContextWraps[instanceId] = Pair(packageName, processSlot)
        Timber.tag(TAG).d("Registered pending context wrap for $instanceId")
    }

    @Volatile internal var lastLaunchInstanceId: String? = null
    @Volatile internal var lastLaunchApkPath: String? = null
    @Volatile internal var lastLaunchPackageName: String? = null

    // Strong reference set to prevent GC of guest LoadedApk objects stored as WeakReference in mPackages
    private val retainedGuestLoadedApks = java.util.Collections.synchronizedSet(mutableSetOf<Any>())

    /**
     * v79 probe (launch102 follow-up): CM's second activity
     * (AppTabFragment) died in performLaunchActivity with an NPE —
     * Resources.addLoaders on a null Resources — 14ms after ART
     * logged "Failed to open APK '<guest apk>': I/O error" on the
     * main thread, a line launch100 (StartPage only) never produced.
     * Two live suspects: (a) the per-launch LoadedApk clone that
     * replaceClassLoader manufactures carries broken resource state;
     * (b) opening the guest APK at that moment is interfered with.
     * This probe runs right after replaceClassLoader, on the exact
     * state AOSP is about to consume, and records: the clone's
     * identity and its mResources field, what clone.getResources()
     * yields here, and whether a plain in-process ZipFile open of
     * the guest APK succeeds at the same moment. A non-null
     * getResources() plus a good zip open convicts the clone's lazy
     * state; a failing zip open convicts the file layer.
     * NOTE: calling getResources() may populate the clone's cache,
     * so a probed launch can heal itself — that outcome is itself
     * the datum (resources were buildable at hook time). Diagnostic
     * only; remove together with the eventual fix.
     */
    private fun probeLaunchResources(
        packageName: String,
        apkPath: String,
        targetActivity: String
    ) {
        runSafe(TAG) {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return@runSafe
            val mPackagesField = findField(atClass, "mPackages")
            mPackagesField?.isAccessible = true
            val mPackages = mPackagesField?.get(activityThread)
                as? android.util.ArrayMap<*, *> ?: return@runSafe
            val clone = (mPackages[packageName]
                as? java.lang.ref.WeakReference<*>)?.get()
            if (clone == null) {
                GuestBreadcrumb.log(
                    "v79 probe target=$targetActivity clone=null"
                )
                return@runSafe
            }
            val resField = findField(clone::class.java, "mResources")
            resField?.isAccessible = true
            val resBefore = resField?.get(clone)
            val zipResult = try {
                val zf = java.util.zip.ZipFile(java.io.File(apkPath))
                val n = zf.size()
                zf.close()
                "ok entries=$n"
            } catch (t: Throwable) {
                "FAIL " + t.javaClass.simpleName + ": " + t.message
            }
            val getResResult = try {
                val m = clone::class.java.getMethod("getResources", atClass)
                m.isAccessible = true
                val r = m.invoke(clone, activityThread)
                if (r == null) "null"
                else "#" + System.identityHashCode(r)
            } catch (t: Throwable) {
                val cause =
                    (t as? java.lang.reflect.InvocationTargetException)
                        ?.targetException ?: t
                "THREW " + cause.javaClass.simpleName + ": " + cause.message
            }
            val resAfter = resField?.get(clone)
            GuestBreadcrumb.log(
                "v79 probe target=$targetActivity clone=#" +
                    System.identityHashCode(clone) +
                    " mResources(before)=" +
                    (resBefore?.let {
                        "#" + System.identityHashCode(it)
                    } ?: "null") +
                    " zipOpen=" + zipResult +
                    " getResources()=" + getResResult +
                    " mResources(after)=" +
                    (resAfter?.let {
                        "#" + System.identityHashCode(it)
                    } ?: "null")
            )
        }
    }

    private val apkWatchStarted =
        java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * v80 watcher turned v81 guard (launch103/104 follow-up): the
     * guest APK copy under files/virtual/apks/<instanceId>.apk was
     * present at StartPage launch and unlinked ~160ms before the
     * AppTab launch; launch104's stack snapshot placed the unlink
     * inside ZWRisk.setup() during FKong init in the agree flow —
     * the SDK deletes the path it reads as its own sourceDir, an
     * unlink that fails harmlessly on a real device (/data/app
     * permissions) but succeeds here (same-uid copy). The copy
     * carries a guard hard link in .apk_guard/ (created by
     * VirtualEngine at install, or here on first watch for older
     * installs). This watchdog polls the file every 50ms for the
     * life of the process and, the moment it vanishes, re-links
     * the visible name from the guard — single-digit ms against
     * an observed ~170ms gap to the next launch. The first
     * transition of a process still snapshots all thread stacks
     * into v80-stacks-<pid>.txt as evidence.
     */
    private fun startApkWatchdog(instanceId: String, apkPath: String) {
        if (!apkWatchStarted.compareAndSet(false, true)) return
        runSafe(TAG) {
            val filesDir = engine.getDataDir(instanceId)?.let {
                java.io.File(it, "files")
            }
            val target = java.io.File(apkPath)
            // v81 guard: VirtualEngine keeps a hard link to the copy
            // at <virtualRoot>/.apk_guard/<same name>; the guest
            // never sees that name, so its unlink of sourceDir can
            // only drop one directory entry, never the bytes.
            val guardFile = java.io.File(
                java.io.File(
                    target.parentFile?.parentFile, ".apk_guard"
                ),
                target.name
            )
            val t = Thread({
                val fmt = java.text.SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.US
                )
                val startMs = System.currentTimeMillis()
                var wasExists = target.exists()
                var lastLen = if (wasExists) target.length() else -1L
                // Instances installed before v81 have no guard link;
                // create it now (same-uid, both dirs owner-writable).
                if (wasExists && !guardFile.exists()) {
                    runSafe(TAG) {
                        guardFile.parentFile?.mkdirs()
                        android.system.Os.link(
                            apkPath, guardFile.absolutePath
                        )
                    }
                }
                GuestBreadcrumb.log(
                    "v81 watch start path=$apkPath exists=$wasExists" +
                        " len=$lastLen guard=" + guardFile.exists()
                )
                var restoreCount = 0
                var dumpedStacks = false
                while (true) {
                    try {
                        Thread.sleep(50)
                    } catch (ie: InterruptedException) {
                        break
                    }
                    val nowExists = target.exists()
                    if (nowExists != wasExists) {
                        val wall = fmt.format(java.util.Date())
                        val afterMs =
                            System.currentTimeMillis() - startMs
                        GuestBreadcrumb.log(
                            "v81 watch TRANSITION " +
                                (if (wasExists) "exists->missing"
                                else "missing->exists") +
                                " wall=" + wall +
                                " afterMs=" + afterMs +
                                " lastLen=" + lastLen
                        )
                        if (wasExists && !nowExists) {
                            // The copy was unlinked (launch104:
                            // ZWRisk.setup does this in the agree
                            // flow). Re-link the visible name from
                            // the guard immediately; the observed
                            // gap to the next activity launch is
                            // ~170ms, this takes single-digit ms.
                            var restored = false
                            var restoreErr = ""
                            if (guardFile.exists()) {
                                for (attempt in 1..5) {
                                    try {
                                        android.system.Os.link(
                                            guardFile.absolutePath,
                                            apkPath
                                        )
                                        restored = target.exists()
                                        if (restored) break
                                    } catch (t2: Throwable) {
                                        restoreErr = t2.toString()
                                    }
                                    try {
                                        Thread.sleep(10)
                                    } catch (ie2: InterruptedException) {
                                        break
                                    }
                                }
                            } else {
                                restoreErr = "guard-missing"
                            }
                            if (restored) restoreCount++
                            GuestBreadcrumb.log(
                                "v81 guard RESTORE ok=$restored" +
                                    " count=$restoreCount wall=" +
                                    fmt.format(java.util.Date()) +
                                    (if (restored) ""
                                    else " err=$restoreErr")
                            )
                            wasExists = restored
                        } else {
                            wasExists = nowExists
                        }
                        // Keep the v80 stack snapshot for the first
                        // transition of the process (validation
                        // evidence for who deleted the copy).
                        if (!dumpedStacks && filesDir != null) {
                            dumpedStacks = true
                            runSafe(TAG) {
                                val out = java.io.File(
                                    filesDir,
                                    "v80-stacks-" +
                                        android.os.Process.myPid() + ".txt"
                                )
                                val sb = StringBuilder()
                                sb.append("transition wall=").append(wall)
                                    .append(" path=").append(apkPath)
                                    .append('\n')
                                for ((thread, stack) in
                                    Thread.getAllStackTraces()) {
                                    sb.append("\n--- \"")
                                        .append(thread.name)
                                        .append("\" ")
                                        .append(thread.state)
                                        .append('\n')
                                    for (el in stack.take(40)) {
                                        sb.append("    at ").append(el)
                                            .append('\n')
                                    }
                                }
                                out.appendText(sb.toString())
                            }
                        }
                    }
                    if (nowExists) lastLen = target.length()
                }
                GuestBreadcrumb.log("v81 watch stop (interrupt)")
            }, "v81-apk-watch")
            t.isDaemon = true
            t.start()
        }
    }

    /**
     * Replace the ClassLoader in ActivityThread's LoadedApk (mPackages) registry.
     * This ensures performLaunchActivity() uses our DexClassLoader to load the guest class.
     *
     * CRITICAL FIX: We must NOT mutate the host's LoadedApk directly — that corrupts
     * the host app's ClassLoader. Instead we:
     * 1. Clone the host's LoadedApk via Unsafe.allocateInstance (no-constructor clone)
     * 2. Copy all fields, then override mClassLoader, mAppDir, mResDir, mPackageName
     * 3. Register the clone under the GUEST package name in mPackages
     * 4. Also register under the HOST package name so performLaunchActivity() finds it
     *    (because ActivityInfo.applicationInfo.packageName was swapped to guest)
     *
     * From Android 16 ActivityThread.java:
     *   mPackages: ArrayMap<String, WeakReference<LoadedApk>>
     *   LoadedApk.mClassLoader: ClassLoader
     */
    private fun replaceClassLoader(packageName: String, instanceId: String, apkPath: String) {
        runSafe(TAG) {
            GuestBreadcrumb.log("replaceClassLoader enter pkg=$packageName instance=$instanceId")
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return@runSafe

            // Get mPackages: ArrayMap<String, WeakReference<LoadedApk>>
            val mPackagesField = findField(atClass, "mPackages")
            mPackagesField?.isAccessible = true
            val mPackages = mPackagesField?.get(activityThread) as? android.util.ArrayMap<*, *> ?: return@runSafe

            // Get the host app's LoadedApk
            val hostPkgName = context.packageName
            val hostRef = mPackages[hostPkgName] as? java.lang.ref.WeakReference<*>
            val hostLoadedApk = hostRef?.get() ?: return@runSafe

            // Get or create the ClassLoader from the engine for this guest app
            val guestClassLoader = engine.getOrCreateClassLoader(instanceId, apkPath)
            GuestBreadcrumb.log(
                "replaceClassLoader host=#" + System.identityHashCode(hostLoadedApk) +
                    " guestCL=" +
                    (guestClassLoader?.let { "#" + System.identityHashCode(it) } ?: "null")
            )
            if (guestClassLoader != null) {
                val loadedApkClass = hostLoadedApk::class.java

                // === Clone the LoadedApk instead of mutating the host's copy ===
                val guestLoadedApk = try {
                    // Use Unsafe.allocateInstance to create without calling constructor
                    val unsafeClass = Class.forName("sun.misc.Unsafe")
                    val theUnsafeField = unsafeClass.getDeclaredField("theUnsafe")
                    theUnsafeField.isAccessible = true
                    val unsafe = theUnsafeField.get(null)
                    val allocMethod = unsafeClass.getDeclaredMethod("allocateInstance", Class::class.java)
                    allocMethod.invoke(unsafe, loadedApkClass)
                } catch (e: Exception) {
                    Timber.tag(TAG).w("Unsafe.allocateInstance failed, using host directly: ${e.message}")
                    null
                }

                val targetLoadedApk = guestLoadedApk ?: hostLoadedApk

                if (guestLoadedApk != null) {
                    // Copy ALL fields from host to clone
                    var currentClass: Class<*>? = loadedApkClass
                    while (currentClass != null && currentClass != Any::class.java) {
                        for (field in currentClass.declaredFields) {
                            if (java.lang.reflect.Modifier.isStatic(field.modifiers)) continue
                            try {
                                field.isAccessible = true
                                field.set(guestLoadedApk, field.get(hostLoadedApk))
                            } catch (_: Exception) { /* skip final fields etc */ }
                        }
                        currentClass = currentClass.superclass
                    }
                }

                // Set guest-specific fields on the clone (NOT the host)
                val classLoaderField = findField(loadedApkClass, "mClassLoader")
                classLoaderField?.isAccessible = true
                classLoaderField?.set(targetLoadedApk, guestClassLoader)

                val appDirField = findField(loadedApkClass, "mAppDir")
                appDirField?.isAccessible = true
                appDirField?.set(targetLoadedApk, apkPath)

                val resDirField = findField(loadedApkClass, "mResDir")
                resDirField?.isAccessible = true
                resDirField?.set(targetLoadedApk, apkPath)

                // Patch mApplicationInfo on the cloned LoadedApk so that
                // Runtime.nativeLoad() finds the correct nativeLibraryDir.
                // Without this, the LoadedApk has HOST paths and native lib
                // loading fails with SIGABRT.
                val loadedApkAppInfoField = findField(loadedApkClass, "mApplicationInfo")
                loadedApkAppInfoField?.isAccessible = true
                val loadedApkAppInfo = loadedApkAppInfoField?.get(targetLoadedApk) as? android.content.pm.ApplicationInfo
                if (loadedApkAppInfo != null) {
                    loadedApkAppInfo.sourceDir = apkPath
                    loadedApkAppInfo.publicSourceDir = apkPath
                    val nativeLibDir = engine.getNativeLibDir(instanceId)
                    if (nativeLibDir != null) {
                        loadedApkAppInfo.nativeLibraryDir = nativeLibDir
                    }
                    val dataDir = engine.getDataDir(instanceId)
                    if (dataDir != null) {
                        loadedApkAppInfo.dataDir = dataDir
                    }
                }

                val pkgField = findField(loadedApkClass, "mPackageName")
                pkgField?.isAccessible = true
                // Keep mPackageName as HOST package so ContextImpl's mOpPackageName and
                // mAttributionSource use the host package name. This prevents
                // AppOpsManager.checkPackage(hostUid, guestPkg) SecurityException when
                // guest code accesses Settings/ContentProviders via IPC.
                // VirtualContext wrapping (applied in callActivityOnCreate) will override
                // getPackageName() to return the guest package for guest app code.
                pkgField?.set(targetLoadedApk, hostPkgName)

                // === FIX: Set mApplication on the cloned LoadedApk to the guest Application ===
                // When the framework calls performLaunchActivity(), it does:
                //   Application app = r.packageInfo.makeApplication(false, mInstrumentation)
                // This returns LoadedApk.mApplication. If we don't set it to the guest's
                // Application, it returns NextVmApplication (the host), causing crashes
                // in apps using Dagger/Hilt that cast getApplication() to their own type.
                // This fixes Play Store crash: "NextVmApplication does not implement interface bwwh"
                val mApplicationField = findField(loadedApkClass, "mApplication")
                mApplicationField?.isAccessible = true
                val guestApp = engine.getGuestApplication(instanceId)
                if (guestApp != null) {
                    mApplicationField?.set(targetLoadedApk, guestApp)
                    Timber.tag(TAG).d("Set mApplication on guest LoadedApk to guest Application for $instanceId")
                }

                // Register the guest LoadedApk under the guest package name in mPackages
                // Use WeakReference to match framework expectations, but also keep a strong
                // reference in our retention set to prevent premature GC
                @Suppress("UNCHECKED_CAST")
                val typedPackages = mPackages as android.util.ArrayMap<String, Any>
                typedPackages[packageName] = java.lang.ref.WeakReference(targetLoadedApk)
                retainedGuestLoadedApks.add(targetLoadedApk)

                // Also register under host package name so performLaunchActivity()
                // can find a LoadedApk with the guest ClassLoader when it looks up
                // the ActivityInfo's packageName (which we swapped to guest)
                // IMPORTANT: Save and restore host LoadedApk afterwards
                savedHostLoadedApk = hostLoadedApk
                savedHostClassLoader = classLoaderField?.get(hostLoadedApk) as? ClassLoader

                // Set thread's context ClassLoader to the guest ClassLoader.
                // Some framework code (including AppComponentFactory.instantiateActivity)
                // uses Thread.currentThread().contextClassLoader to load classes.
                Thread.currentThread().contextClassLoader = guestClassLoader

                // Register in the global ClassLoader registry (ensures newActivity can find it)
                GuestClassLoaderRegistry.register(packageName, instanceId, guestClassLoader)

                // Also inject via VirtualClassLoaderInjector as a secondary guarantee
                VirtualClassLoaderInjector.inject(
                    packageName = packageName,
                    classLoader = guestClassLoader,
                    hostPackageName = hostPkgName
                )

                val guestRefNow =
                    (typedPackages[packageName] as? java.lang.ref.WeakReference<*>)?.get()
                val hostRefNow =
                    (typedPackages[hostPkgName] as? java.lang.ref.WeakReference<*>)?.get()
                GuestBreadcrumb.log(
                    "replaceClassLoader done pkg=$packageName target=#" +
                        System.identityHashCode(targetLoadedApk) +
                        " mPackages[guest]=#" +
                        (guestRefNow?.let { System.identityHashCode(it) } ?: -1) +
                        " mPackages[host]=#" +
                        (hostRefNow?.let { System.identityHashCode(it) } ?: -1)
                )
                Timber.tag(TAG).d("ClassLoader replaced for $packageName (instance: $instanceId)")
            } else {
                Timber.tag(TAG).w("No ClassLoader available for $instanceId — class loading may fail")
            }
        }
    }

    // Saved host state for restoration after guest launch
    @Volatile private var savedHostLoadedApk: Any? = null
    @Volatile private var savedHostClassLoader: ClassLoader? = null

    // ==================== Token Pre-Registration ====================

    /**
     * Pre-register a stub activity token in ActivityThread.mActivities so that
     * TransactionExecutor can find the ActivityClientRecord when it calls
     * getActivityClient(token). Without this, the framework crashes with
     * "Target activity: Not found for token".
     *
     * We allocate a blank ActivityClientRecord via Unsafe (no constructor),
     * populate its key fields, and insert it into the mActivities map.
     */
    private fun preRegisterActivityToken(token: IBinder, info: ActivityInfo, intent: Intent) {
        runSafe(TAG) {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return@runSafe

            // Get mActivities: ArrayMap<IBinder, ActivityClientRecord>
            val mActivitiesField = findField(atClass, "mActivities")
            mActivitiesField?.isAccessible = true
            val mActivities = mActivitiesField?.get(activityThread)
                    as? android.util.ArrayMap<IBinder, Any> ?: return@runSafe

            // If this token is already registered, skip
            if (mActivities.containsKey(token)) {
                Timber.tag(TAG).d("Token already in mActivities, skipping pre-registration")
                return@runSafe
            }

            // Allocate an ActivityClientRecord without calling its constructor
            val acrClass = Class.forName("android.app.ActivityThread\$ActivityClientRecord")
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            val theUnsafeField = unsafeClass.getDeclaredField("theUnsafe")
            theUnsafeField.isAccessible = true
            val unsafe = theUnsafeField.get(null)
            val allocMethod = unsafeClass.getDeclaredMethod("allocateInstance", Class::class.java)
            val record = allocMethod.invoke(unsafe, acrClass) ?: return@runSafe

            // Populate essential fields
            setFieldSafe(record, "token", token)
            setFieldSafe(record, "intent", intent)
            setFieldSafe(record, "activityInfo", info)

            // Attach the host's LoadedApk (packageInfo) so the record is viable
            val mPackagesField = findField(atClass, "mPackages")
            mPackagesField?.isAccessible = true
            val mPackages = mPackagesField?.get(activityThread) as? android.util.ArrayMap<*, *>
            if (mPackages != null) {
                val hostPkg = context.packageName
                val ref = mPackages[hostPkg] as? java.lang.ref.WeakReference<*>
                val loadedApk = ref?.get()
                if (loadedApk != null) {
                    setFieldSafe(record, "packageInfo", loadedApk)
                }
            }

            mActivities[token] = record
            Timber.tag(TAG).i("Pre-registered activity token in mActivities")
        }
    }

    /**
     * Try to resolve an AppCompat theme from the guest APK's Resources.
     * Looks for common AppCompat theme resource names by identifier.
     */
    private fun tryResolveAppCompatTheme(resources: android.content.res.Resources, packageName: String): Int {
        val themeNames = listOf(
            "Theme_AppCompat_DayNight",
            "Theme_AppCompat_Light",
            "Theme_AppCompat",
            "Theme_AppCompat_Light_DarkActionBar",
            "Theme_AppCompat_DayNight_DarkActionBar",
            "AppTheme",
            "Theme_App"
        )
        for (name in themeNames) {
            try {
                val resId = resources.getIdentifier(name, "style", packageName)
                if (resId != 0) {
                    Timber.tag(TAG).d("Resolved AppCompat theme from guest: $name = 0x${resId.toString(16)}")
                    return resId
                }
            } catch (_: Exception) { }
        }
        return 0
    }

    /**
     * Parse theme resource IDs directly from APK manifest.
     * Used as a fallback when the PackageManagerProxy hasn't cached the app yet
     * (race condition: Activity launch arrives before registerApp completes).
     *
     * @return Pair(activityTheme, appTheme) — either may be 0
     */
    private fun parseThemeFromApk(
        apkPath: String,
        activityName: String
    ): Pair<Int, Int> {
        return try {
            val am = android.content.res.AssetManager::class.java.getDeclaredConstructor().newInstance()
            val addAssetPath = android.content.res.AssetManager::class.java
                .getDeclaredMethod("addAssetPath", String::class.java)
            addAssetPath.isAccessible = true
            addAssetPath.invoke(am, apkPath)

            val parser = am.openXmlResourceParser("AndroidManifest.xml")
            var appTheme = 0
            var activityTheme = 0
            var packageName = ""
            val androidNs = "http://schemas.android.com/apk/res/android"

            var eventType = parser.eventType
            while (eventType != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                if (eventType == org.xmlpull.v1.XmlPullParser.START_TAG) {
                    when (parser.name) {
                        "manifest" -> {
                            packageName = parser.getAttributeValue(null, "package") ?: ""
                        }
                        "application" -> {
                            appTheme = parser.getAttributeResourceValue(androidNs, "theme", 0)
                        }
                        "activity", "activity-alias" -> {
                            val name = parser.getAttributeValue(androidNs, "name") ?: ""
                            val resolved = if (name.startsWith(".")) "$packageName$name"
                                else if (!name.contains(".")) "$packageName.$name"
                                else name
                            if (resolved == activityName) {
                                activityTheme = parser.getAttributeResourceValue(androidNs, "theme", 0)
                            }
                        }
                    }
                }
                eventType = parser.next()
            }
            parser.close()
            am.close()
            Pair(activityTheme, appTheme)
        } catch (e: Exception) {
            Timber.tag(TAG).w("parseThemeFromApk failed: ${e.message}")
            Pair(0, 0)
        }
    }

    /**
     * Reflectively set a field on an object, walking the superclass chain.
     * Silently logs a warning if the field is not found or cannot be set.
     */
    private fun setFieldSafe(obj: Any, fieldName: String, value: Any?) {
        try {
            val field = findField(obj::class.java, fieldName)
            if (field != null) {
                field.isAccessible = true
                field.set(obj, value)
            } else {
                Timber.tag(TAG).w("setFieldSafe: field '$fieldName' not found on ${obj::class.java.name}")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w("setFieldSafe: failed to set '$fieldName': ${e.message}")
        }
    }

    /**
     * Restore the host LoadedApk after a guest activity launch completes.
     * Called from NextVmInstrumentation after activity instantiation.
     */
    internal fun restoreHostLoadedApk() {
        val hostApk = savedHostLoadedApk ?: return
        val hostCl = savedHostClassLoader ?: return
        runSafe(TAG) {
            val classLoaderField = findField(hostApk::class.java, "mClassLoader")
            classLoaderField?.isAccessible = true
            // Only restore if it was changed
            val currentCl = classLoaderField?.get(hostApk)
            if (currentCl != hostCl) {
                classLoaderField?.set(hostApk, hostCl)
                Timber.tag(TAG).d("Host LoadedApk ClassLoader restored")
            }
        }
        savedHostLoadedApk = null
        savedHostClassLoader = null
    }

    /**
     * Get the guest ClassLoader for a given target class name.
     * Used by NextVmInstrumentation.newActivity() to load guest classes
     * with the correct DexClassLoader instead of the system one.
     */
    internal fun getGuestClassLoaderForLaunch(): ClassLoader? {
        val instanceId = lastLaunchInstanceId ?: return null
        val apkPath = lastLaunchApkPath ?: return null
        return engine.getOrCreateClassLoader(instanceId, apkPath)
    }

    /**
     * Resolve an activity class name, handling activity-aliases.
     * Used by NextVmInstrumentation.newActivity() as a fallback when
     * ClassNotFoundException occurs (the alias class doesn't exist).
     */
    internal fun resolveActivityClassForLaunch(className: String): String {
        val packageName = lastLaunchPackageName ?: return className
        return engine.resolveActivityAlias(packageName, className)
    }

    /**
     * Get the guest Application instance for the current launch.
     * Its ClassLoader is proven to work (Application boot succeeded).
     */
    internal fun getGuestApplicationForLaunch(): Application? {
        val instanceId = lastLaunchInstanceId ?: return null
        return engine.getGuestApplication(instanceId)
    }

    /**
     * Hook Instrumentation to inject resources/context AFTER Activity.attach()
     * but BEFORE Activity.onCreate().
     *
     * From Android 16 ActivityThread.java:
     *   mInstrumentation field holds the Instrumentation instance
     *   We replace it with a wrapper that intercepts callActivityOnCreate()
     */
    private fun hookInstrumentationIfNeeded() {
        if (instrumentationHooked) return

        runSafe(TAG) {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return@runSafe

            val instrField = findField(atClass, "mInstrumentation")
            instrField?.isAccessible = true
            val originalInstr = instrField?.get(activityThread) as? android.app.Instrumentation
                ?: return@runSafe

            // Only wrap once
            if (originalInstr::class.java.name.contains("NextVm")) return@runSafe

            val proxyInstr = NextVmInstrumentation(originalInstr, this)
            instrField.set(activityThread, proxyInstr)
            instrumentationHooked = true
            Timber.tag(TAG).d("Instrumentation hooked for post-create injection")
        }
    }

    /**
     * Called by NextVmInstrumentation AFTER Activity.attach() but BEFORE Activity.onCreate().
     * This is the injection point for resources, theme, and context wrapping.
     */
    internal fun onActivityPreCreate(activity: android.app.Activity) {
        com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
            .log("preCreate enter " + activity.javaClass.name)
        var instanceId = lastLaunchInstanceId
        var apkPath = lastLaunchApkPath
        var packageName = lastLaunchPackageName

        // === FALLBACK: Resolve from Activity's ClassLoader or intent ===
        // When a guest app internally starts another Activity (e.g., Play Store's
        // MainActivity → AssetBrowserActivity), the second launch may bypass our stub
        // system or arrive after lastLaunchInstanceId has been cleared. In this case,
        // resolve the instanceId by matching the Activity's ClassLoader against the
        // GuestClassLoaderRegistry, or from the intent extras.
        if (instanceId == null || apkPath == null || packageName == null) {
            val activityCl = activity::class.java.classLoader
            // Try to find instanceId from the Activity's intent, preserving
            // any launch fields that are already available.
            val intent = runSafe(TAG) { activity.intent }
            instanceId = intent?.getStringExtra(VirtualIntentExtras.INSTANCE_ID) ?: instanceId
            apkPath = intent?.getStringExtra(VirtualIntentExtras.APK_PATH) ?: apkPath
            packageName = intent?.getStringExtra(VirtualIntentExtras.TARGET_PACKAGE) ?: packageName

            // If an instance ID is already known, recover any missing fields
            // from the authoritative VirtualApp record first.
            instanceId?.let { knownInstanceId ->
                engine.findApp(knownInstanceId)?.let { app ->
                    if (apkPath == null) apkPath = app.apkPath
                    if (packageName == null) packageName = app.packageName
                }
            }

            // If any launch field is still missing, resolve from the Activity's
            // exact ClassLoader or from the process-wide registry.
            if ((instanceId == null || apkPath == null || packageName == null) && activityCl != null) {
                val app = engine.findAppByClassLoader(activityCl)
                if (app != null) {
                    instanceId = app.instanceId
                    apkPath = app.apkPath
                    packageName = app.packageName
                    Timber.tag(TAG).d("Resolved instanceId from ClassLoader for ${activity::class.java.name}: $instanceId")
                }
                // The engine's local classLoader map can contain a different loader
                // instance from the one used by Instrumentation.newActivity(). The
                // process-wide registry is authoritative for that exact object.
                if (instanceId == null || apkPath == null || packageName == null) {
                    val registryInstanceId =
                        GuestClassLoaderRegistry.findInstanceIdByClassLoader(activityCl)
                    if (registryInstanceId != null) {
                        val registryApp = engine.findApp(registryInstanceId)
                        if (registryApp != null) {
                            instanceId = registryApp.instanceId
                            apkPath = registryApp.apkPath
                            packageName = registryApp.packageName
                            Timber.tag(TAG).d(
                                "Resolved instanceId from registry ClassLoader for " +
                                    "${activity::class.java.name}: $instanceId"
                            )
                        }
                    }
                }

                // Last fallback for framework-created Activities whose ClassLoader
                // object is not the registered exact instance.
                if (instanceId == null || apkPath == null || packageName == null) {
                    val activityPackageName =
                        runSafe(TAG) { activity.applicationInfo?.packageName }
                    val packageApp =
                        activityPackageName?.let { engine.findAppByPackage(it) }
                    if (packageApp != null) {
                        instanceId = packageApp.instanceId
                        apkPath = packageApp.apkPath
                        packageName = packageApp.packageName
                        Timber.tag(TAG).d(
                            "Resolved instanceId from Activity package for " +
                                "${activity::class.java.name}: $instanceId"
                        )
                    }
                }
            }
        }

        if (instanceId == null || apkPath == null || packageName == null) {
            Timber.tag(TAG).w(
                "Skipping pre-create injection for ${activity::class.java.name}: " +
                    "instanceId=$instanceId apkPath=${apkPath != null} packageName=$packageName"
            )
            return
        }

        Timber.tag(TAG).d("Pre-create injection for activity ${activity::class.java.name} (instance: $instanceId)")

        // Get the guest ClassLoader (needed for resource loading)
        val guestClassLoader = engine.getOrCreateClassLoader(instanceId, apkPath)

        // 1. Inject resources from guest APK using the GUEST ClassLoader
        var guestResources: android.content.res.Resources? = null
        runSafe(TAG) {
            engine.getResourceManager()?.let { resMgr ->
                guestResources = resMgr.createResourcesForApp(
                    context = context,
                    apkPath = apkPath,
                    classLoader = guestClassLoader,
                    instanceId = instanceId
                )
                if (guestResources != null) {
                    resMgr.injectResourcesIntoActivity(activity, guestResources!!)
                    Timber.tag(TAG).d("Resources injected for $instanceId")
                }
            }
        }

        // 2. Apply guest app's theme
        runSafe(TAG) {
            val activityName = activity::class.java.name
            var themeResId = engine.getActivityThemeResId(packageName, activityName)

            // Fallback: try metaData-based theme
            if (themeResId == 0) {
                themeResId = engine.getThemeResId(instanceId)
            }

            // Fallback: parse theme directly from APK manifest
            // Needed when Activity launches before registerApp() finishes on background thread
            if (themeResId == 0 && apkPath != null) {
                val (actTheme, appTheme) = parseThemeFromApk(apkPath, activityName)
                themeResId = if (actTheme != 0) actTheme else appTheme
                if (themeResId != 0) {
                    Timber.tag(TAG).d("Resolved theme from APK manifest: 0x${themeResId.toString(16)}")
                }
            }

            // Fallback: search for AppCompat theme in guest Resources
            if (themeResId == 0 && guestResources != null) {
                themeResId = tryResolveAppCompatTheme(guestResources!!, packageName)
            }

            if (themeResId != 0 && guestResources != null) {
                engine.getResourceManager()?.applyTheme(activity, themeResId, guestResources!!)
                Timber.tag(TAG).d("Theme applied for $instanceId (resId=0x${themeResId.toString(16)})")
            } else if (guestResources != null) {
                // Last resort: apply a Theme.AppCompat from guest resources via getIdentifier
                // Host theme IDs won't resolve with guest resources, so find one in the guest APK
                var fallbackApplied = false
                try {
                    // Try to find ANY AppCompat theme in the guest's resources
                    val guestAppCompatId = guestResources!!.getIdentifier(
                        "Theme_AppCompat_Light_DarkActionBar", "style", packageName
                    )
                    if (guestAppCompatId != 0) {
                        activity.setTheme(guestAppCompatId)
                        fallbackApplied = true
                        Timber.tag(TAG).w("Applied guest AppCompat fallback theme for $instanceId")
                    }
                } catch (_: Exception) {}
                if (!fallbackApplied) {
                    // Absolute last resort: framework theme (works with any Resources)
                    activity.setTheme(android.R.style.Theme_DeviceDefault_Light_DarkActionBar)
                    Timber.tag(TAG).w("Applied framework fallback theme for $instanceId")
                }
            }
        }

        // 3. Wrap with VirtualContext for file isolation + getPackageName() fix
        runSafe(TAG) {
            engine.wrapActivityContext(activity, instanceId, packageName)
        }

        // 3.5 Inject guest Resources into the VirtualContext wrapper
        // so Activity.getResources() returns guest resources
        runSafe(TAG) {
            if (guestResources != null) {
                val mBaseField = android.content.ContextWrapper::class.java.getDeclaredField("mBase")
                mBaseField.isAccessible = true
                val base = mBaseField.get(activity)
                if (base is com.nextvm.core.sandbox.VirtualContext) {
                    base.setGuestResources(guestResources!!)
                    Timber.tag(TAG).d("Guest Resources set on VirtualContext for $instanceId")
                }
            }
        }

        // 4. Set mApplication to guest Application instance
        runSafe(TAG) {
            val guestApp = engine.getGuestApplication(instanceId)
            if (guestApp != null) {
                val mApplicationField = findField(android.app.Activity::class.java, "mApplication")
                mApplicationField?.isAccessible = true
                mApplicationField?.set(activity, guestApp)
                Timber.tag(TAG).d("mApplication set to guest Application for $instanceId")
            }
        }

        // Clear pending data
        pendingResourceInjections.remove(instanceId)
        pendingContextWraps.remove(instanceId)
        lastLaunchInstanceId = null
        lastLaunchApkPath = null
        lastLaunchPackageName = null
    }

    /**
     * Handle legacy LAUNCH_ACTIVITY (100) for pre-Android 9 devices.
     * (Kept for compatibility, but Android 16 uses EXECUTE_TRANSACTION exclusively)
     */
    private fun handleLegacyLaunchActivity(msg: Message): Boolean {
        if (AndroidCompat.isAtLeastP) return false // Not used on Android 9+

        try {
            val record = msg.obj ?: return false
            val intentField = findField(record::class.java, "intent")
            intentField?.isAccessible = true
            val intent = intentField?.get(record) as? Intent ?: return false

            val targetActivity = intent.getStringExtra(VirtualIntentExtras.TARGET_ACTIVITY)
                ?: return false

            val activityInfoField = findField(record::class.java, "activityInfo")
            activityInfoField?.isAccessible = true
            val activityInfo = activityInfoField?.get(record)

            if (activityInfo != null) {
                val nameField = findField(activityInfo::class.java, "name")
                nameField?.isAccessible = true
                nameField?.set(activityInfo, targetActivity)
            }

            Timber.tag(TAG).d("Legacy class swap: $targetActivity")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in legacy LAUNCH_ACTIVITY handler")
        }

        return false
    }

    /**
     * Handle CREATE_SERVICE (114) — Service creation interception.
     *
     * msg.obj = CreateServiceData with:
     *   - token: IBinder
     *   - info: ServiceInfo (contains name, packageName, applicationInfo)
     *   - compatInfo: CompatibilityInfo
     *   - intent: Intent (may have our NEXTVM extras)
     */
    private fun handleCreateService(msg: Message): Boolean {
        val data = msg.obj ?: return false

        try {
            val dataClass = data::class.java

            // Get ServiceInfo from CreateServiceData
            val infoField = findField(dataClass, "info")
            infoField?.isAccessible = true
            val serviceInfo = infoField?.get(data) ?: return false

            // Try to get intent with NEXTVM extras
            // In some Android versions, CreateServiceData may have an intent
            val intentField = findField(dataClass, "intent")
            intentField?.isAccessible = true
            val intent = intentField?.get(data) as? Intent

            // Check if this service was started by NEXTVM
            val targetPackage = intent?.getStringExtra(VirtualIntentExtras.TARGET_PACKAGE)
            val targetService = intent?.getStringExtra("_nextvm_target_service")
            val instanceId = intent?.getStringExtra(VirtualIntentExtras.INSTANCE_ID)
            val apkPath = intent?.getStringExtra(VirtualIntentExtras.APK_PATH)

            if (targetPackage != null && targetService != null && instanceId != null && apkPath != null) {
                Timber.tag(TAG).i("Intercepted stub service → swapping to $targetService ($targetPackage)")

                val siClass = serviceInfo::class.java

                // Swap ServiceInfo.name
                val nameField2 = findField(siClass, "name")
                nameField2?.isAccessible = true
                nameField2?.set(serviceInfo, targetService)

                // Swap ServiceInfo.packageName
                val pkgField = findField(siClass, "packageName")
                pkgField?.isAccessible = true
                pkgField?.set(serviceInfo, targetPackage)

                // Swap applicationInfo
                val appInfoField = findField(siClass, "applicationInfo")
                appInfoField?.isAccessible = true
                val appInfo = appInfoField?.get(serviceInfo)
                if (appInfo != null) {
                    val aiPkgField = findField(appInfo::class.java, "packageName")
                    aiPkgField?.isAccessible = true
                    aiPkgField?.set(appInfo, targetPackage)

                    val srcDirField = findField(appInfo::class.java, "sourceDir")
                    srcDirField?.isAccessible = true
                    srcDirField?.set(appInfo, apkPath)

                    val pubSrcDirField = findField(appInfo::class.java, "publicSourceDir")
                    pubSrcDirField?.isAccessible = true
                    pubSrcDirField?.set(appInfo, apkPath)

                    val dataDirStr = engine.getDataDir(instanceId)
                    if (dataDirStr != null) {
                        val ddField = findField(appInfo::class.java, "dataDir")
                        ddField?.isAccessible = true
                        ddField?.set(appInfo, dataDirStr)
                    }
                }

                // Replace ClassLoader for this guest package
                replaceClassLoader(targetPackage, instanceId, apkPath)

                Timber.tag(TAG).d("Service class swap complete: $targetService (instance: $instanceId)")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in CREATE_SERVICE handler")
        }

        return false
    }

    /**
     * Handle RECEIVER (113) — BroadcastReceiver dispatch interception.
     *
     * msg.obj = ReceiverData with:
     *   - intent: Intent (the broadcast)
     *   - info: ActivityInfo (receiver info, confusingly named)
     *   - compatInfo: CompatibilityInfo
     */
    private fun handleReceiver(msg: Message): Boolean {
        val data = msg.obj ?: return false

        try {
            val dataClass = data::class.java

            // Get the broadcast intent
            val intentField = findField(dataClass, "intent")
            intentField?.isAccessible = true
            val intent = intentField?.get(data) as? Intent ?: return false

            // Check for NEXTVM receiver metadata
            val targetPackage = intent.getStringExtra(VirtualIntentExtras.TARGET_PACKAGE)
            val targetReceiver = intent.getStringExtra("_nextvm_target_receiver")
            val instanceId = intent.getStringExtra(VirtualIntentExtras.INSTANCE_ID)
            val apkPath = intent.getStringExtra(VirtualIntentExtras.APK_PATH)

            if (targetPackage != null && targetReceiver != null && instanceId != null && apkPath != null) {
                Timber.tag(TAG).i("Intercepted stub receiver → swapping to $targetReceiver ($targetPackage)")

                // Get receiver info (stored as ActivityInfo in ReceiverData)
                val infoField = findField(dataClass, "info")
                infoField?.isAccessible = true
                val receiverInfo = infoField?.get(data)

                if (receiverInfo != null) {
                    val riClass = receiverInfo::class.java

                    // Swap name
                    val nameField2 = findField(riClass, "name")
                    nameField2?.isAccessible = true
                    nameField2?.set(receiverInfo, targetReceiver)

                    // Swap packageName
                    val pkgField = findField(riClass, "packageName")
                    pkgField?.isAccessible = true
                    pkgField?.set(receiverInfo, targetPackage)

                    // Swap applicationInfo
                    val appInfoField = findField(riClass, "applicationInfo")
                    appInfoField?.isAccessible = true
                    val appInfo = appInfoField?.get(receiverInfo)
                    if (appInfo != null) {
                        val aiPkgField = findField(appInfo::class.java, "packageName")
                        aiPkgField?.isAccessible = true
                        aiPkgField?.set(appInfo, targetPackage)

                        val srcDirField = findField(appInfo::class.java, "sourceDir")
                        srcDirField?.isAccessible = true
                        srcDirField?.set(appInfo, apkPath)

                        val pubSrcDirField = findField(appInfo::class.java, "publicSourceDir")
                        pubSrcDirField?.isAccessible = true
                        pubSrcDirField?.set(appInfo, apkPath)
                    }
                }

                // Replace ClassLoader
                replaceClassLoader(targetPackage, instanceId, apkPath)

                Timber.tag(TAG).d("Receiver class swap complete: $targetReceiver (instance: $instanceId)")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in RECEIVER handler")
        }

        return false
    }

    /**
     * Uninstall the hook.
     */
    fun uninstall() {
        if (!installed) return

        try {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return

            val mHField = findField(atClass, "mH") ?: return
            mHField.isAccessible = true
            val mH = mHField.get(activityThread) as Handler

            val callbackField = findField(Handler::class.java, "mCallback") ?: return
            callbackField.isAccessible = true

            // Restore original callback
            callbackField.set(mH, originalCallback)
            installed = false
            instrumentationHooked = false
            Timber.tag(TAG).i("ActivityThread.mH hook uninstalled")

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to uninstall hook")
        }
    }
}

/**
 * NextVmInstrumentation — Custom Instrumentation wrapper that intercepts
 * Activity creation to inject resources, theme, and context BEFORE onCreate().
 *
 * From Android 16 Instrumentation.java:
 *   callActivityOnCreate(Activity, Bundle) calls activity.performCreate(icicle)
 *   We intercept BEFORE performCreate to inject virtual resources.
 */
class NextVmInstrumentation(
    private val base: android.app.Instrumentation,
    private val hook: ActivityThreadHook
) : android.app.Instrumentation() {

    companion object {
        private const val TAG = "NextVmInstr"
    }

    override fun callActivityOnCreate(activity: android.app.Activity, icicle: android.os.Bundle?) {
        com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
            .log("instr callActivityOnCreate enter " + activity.javaClass.name)
        // Inject resources, theme, context BEFORE onCreate
        try {
            hook.onActivityPreCreate(activity)
        } catch (e: Exception) {
            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                .logThrowable("onActivityPreCreate FAILED (logged, continuing)", e)
            Timber.tag(TAG).e(e, "Error in pre-create injection for ${activity::class.java.name}")
        }
        try {
            super.callActivityOnCreate(activity, icicle)
            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                .log("instr callActivityOnCreate exit ok " + activity.javaClass.name)
        } catch (e: RuntimeException) {
            // Unwrap UndeclaredThrowableException from Binder proxy invoke
            val cause = e.cause?.cause ?: e.cause ?: e
            if (cause is SecurityException && (
                cause.message?.contains("setSplashScreenTheme") == true ||
                cause.message?.contains("does not own package") == true ||
                cause.message?.contains("Calling uid") == true
            )) {
                com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                    .logThrowable(
                        "instr onCreate SecurityException SWALLOWED mid-onCreate for " +
                            activity.javaClass.name, e)
                Timber.tag(TAG).w("Package ownership SecurityException swallowed in onCreate: ${cause.message}")
                return
            }
            throw e  // re-throw unknown exceptions
        }
    }

    override fun callActivityOnCreate(
        activity: android.app.Activity,
        icicle: android.os.Bundle?,
        persistentState: android.os.PersistableBundle?
    ) {
        com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
            .log("instr callActivityOnCreate(persistable) enter " + activity.javaClass.name)
        try {
            hook.onActivityPreCreate(activity)
        } catch (e: Exception) {
            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                .logThrowable("onActivityPreCreate FAILED (logged, continuing)", e)
            Timber.tag(TAG).e(e, "Error in pre-create injection for ${activity::class.java.name}")
        }
        try {
            super.callActivityOnCreate(activity, icicle, persistentState)
            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                .log("instr callActivityOnCreate(persistable) exit ok " + activity.javaClass.name)
        } catch (e: RuntimeException) {
            val cause = e.cause?.cause ?: e.cause ?: e
            if (cause is SecurityException) {
                com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                    .logThrowable(
                        "instr onCreate(persistable) SecurityException SWALLOWED mid-onCreate for " +
                            activity.javaClass.name, e)
                Timber.tag(TAG).w("SecurityException in onCreate (PersistableBundle) swallowed: ${cause.message}")
                return
            }
            throw e
        }
    }

    // Delegate all other Instrumentation methods to base
    override fun newActivity(cl: ClassLoader?, className: String?, intent: Intent?): android.app.Activity {
        com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
            .log("instr newActivity " + className)
        // CRITICAL FIX: The ClassLoader 'cl' passed by performLaunchActivity() may be the
        // host app's ClassLoader. We use the GuestClassLoaderRegistry to find the right one.
        //
        // ALIAS FIX: The className may be an activity-alias (no real Java class).
        // Resolve to the real targetActivity first.
        if (className != null) {
            // FIX 1: Extract from intent extras directly — immune to race conditions
            // on volatile fields. The intent still carries all NEXTVM extras at this point.
            val packageName = intent?.getStringExtra(VirtualIntentExtras.TARGET_PACKAGE)
                ?: hook.lastLaunchPackageName
            val instanceId = intent?.getStringExtra(VirtualIntentExtras.INSTANCE_ID)
                ?: hook.lastLaunchInstanceId

            // Resolve activity-alias to real class name
            val resolvedClassName = hook.resolveActivityClassForLaunch(className)
            if (resolvedClassName != className) {
                Timber.tag(TAG).i("newActivity: resolved alias $className → $resolvedClassName")
            }

            val classNamesToTry = if (resolvedClassName != className) {
                listOf(resolvedClassName, className)
            } else {
                listOf(className)
            }

            // Collect candidate ClassLoaders in priority order
            val candidateLoaders = mutableListOf<Pair<String, ClassLoader>>()

            // 1. Registry by instanceId (most specific)
            if (instanceId != null) {
                GuestClassLoaderRegistry.getByInstanceId(instanceId)?.let {
                    candidateLoaders.add("registry[instanceId]" to it)
                }
            }

            // 2. Registry by packageName
            if (packageName != null) {
                GuestClassLoaderRegistry.getByPackage(packageName)?.let { cl2 ->
                    if (candidateLoaders.none { it.second === cl2 }) {
                        candidateLoaders.add("registry[package]" to cl2)
                    }
                }
            }

            // 3. Guest Application's ClassLoader
            val guestApp = hook.getGuestApplicationForLaunch()
            guestApp?.classLoader?.let { appCl ->
                if (candidateLoaders.none { it.second === appCl }) {
                    candidateLoaders.add("guestApp" to appCl)
                }
            }

            // 4. Engine's getGuestClassLoaderForLaunch (legacy path)
            hook.getGuestClassLoaderForLaunch()?.let { engineCl ->
                if (candidateLoaders.none { it.second === engineCl }) {
                    candidateLoaders.add("engine" to engineCl)
                }
            }

            // 5. Framework-provided ClassLoader
            if (cl != null && candidateLoaders.none { it.second === cl }) {
                candidateLoaders.add("framework" to cl)
            }

            // 6. All registered loaders as last resort
            GuestClassLoaderRegistry.getAllLoaders().forEach { allCl ->
                if (candidateLoaders.none { it.second === allCl }) {
                    candidateLoaders.add("registry[all]" to allCl)
                }
            }

            // Try each ClassLoader × each class name
            for (targetName in classNamesToTry) {
                for ((source, loader) in candidateLoaders) {
                    try {
                        val activityClass = loader.loadClass(targetName)
                        val activity = activityClass.getDeclaredConstructor().newInstance() as android.app.Activity
                        Timber.tag(TAG).d("Activity created via $source: $targetName")

                        // Ensure LoadedApk injection is done for this package
                        if (packageName != null) {
                            VirtualClassLoaderInjector.inject(
                                packageName = packageName,
                                classLoader = loader,
                                hostPackageName = hook.hostPackageName
                            )
                        }

                        return activity
                    } catch (_: ClassNotFoundException) {
                        // Try next
                    } catch (e: Exception) {
                        Timber.tag(TAG).w(e, "Error creating activity via $source: $targetName")
                    }
                }
            }

            Timber.tag(TAG).w("All ClassLoader strategies failed for $className (resolved: $resolvedClassName)")
        }

        // Final fallback: use the base Instrumentation with resolved name
        val fallbackName = if (className != null) {
            hook.resolveActivityClassForLaunch(className).takeIf { it != className } ?: className
        } else {
            className
        }
        Timber.tag(TAG).w("Using base Instrumentation for $fallbackName")
        return base.newActivity(cl, fallbackName, intent)
    }

    override fun newApplication(cl: ClassLoader?, className: String?, context: Context?): android.app.Application {
        com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
            .log(
                "instr newApplication " + className +
                    " clId=" + System.identityHashCode(cl)
            )
        return base.newApplication(cl, className, context)
    }

    /**
     * Override callActivityOnDestroy to guard against guest apps calling
     * Process.killProcess(myPid()) during onDestroy().
     *
     * Unity games (and some other apps) call Process.killProcess() in their
     * Activity.onDestroy() to ensure a clean shutdown. In a virtual environment,
     * this kills the entire host process slot. We temporarily replace the
     * Process.killProcess static method behavior by installing a SecurityManager
     * that blocks System.exit(), and wrapping the call with a process-kill guard.
     */
    override fun callActivityOnDestroy(activity: android.app.Activity) {
        val isGuest = GuestClassLoaderRegistry.isGuestClassLoader(activity::class.java.classLoader)
        if (isGuest) {
            com.nextvm.core.virtualization.lifecycle.GuestBreadcrumb
                .log("instr callActivityOnDestroy " + activity.javaClass.name)
            Timber.tag(TAG).d("callActivityOnDestroy for guest: ${activity::class.java.name}")
            // Install Process.killProcess guard before guest onDestroy
            val guard = ProcessKillGuard.install()
            try {
                super.callActivityOnDestroy(activity)
            } catch (e: ProcessKillGuard.KillInterceptedException) {
                Timber.tag(TAG).i("Blocked Process.killProcess/System.exit from guest onDestroy")
            } catch (e: SecurityException) {
                if (e.message?.contains("System.exit") == true) {
                    Timber.tag(TAG).i("Blocked System.exit from guest onDestroy")
                } else {
                    throw e
                }
            } finally {
                guard.uninstall()
            }
        } else {
            super.callActivityOnDestroy(activity)
        }
    }
}

/**
 * ProcessKillGuard — Prevents guest apps from killing the host process.
 *
 * Unity and some other apps call Process.killProcess(Process.myPid()) or
 * System.exit(0) during Activity.onDestroy(). In a virtual environment,
 * this kills the entire host process slot (e.g., :p0).
 *
 * This guard works by:
 * 1. Installing a SecurityManager that blocks System.exit() calls
 * 2. Setting a thread-local flag that can be checked by hooked methods
 *
 * Note: Process.killProcess() calls kill(2) via JNI — it cannot be intercepted
 * at the Java level without native hooks (LSPlant/Dobby). This guard handles
 * the System.exit() case. For Process.killProcess(), native hooking is required
 * for a complete solution.
 */
class ProcessKillGuard private constructor() {
    class KillInterceptedException : RuntimeException("Process kill blocked by NEXTVM")

    companion object {
        private const val TAG = "KillGuard"
        private val guardActive = ThreadLocal<Boolean>()

        fun install(): ProcessKillGuard {
            guardActive.set(true)

            // Install SecurityManager to block System.exit()
            try {
                @Suppress("DEPRECATION")
                val existingManager = System.getSecurityManager()
                if (existingManager !is NextVmSecurityManager) {
                    System.setSecurityManager(NextVmSecurityManager(existingManager))
                }
            } catch (e: Exception) {
                // SecurityManager may not be settable on all Android versions
                Timber.tag(TAG).d("Could not install SecurityManager: ${e.message}")
            }

            return ProcessKillGuard()
        }

        fun isActive(): Boolean = guardActive.get() == true
    }

    fun uninstall() {
        guardActive.set(false)
        try {
            @Suppress("DEPRECATION")
            val current = System.getSecurityManager()
            if (current is NextVmSecurityManager) {
                System.setSecurityManager(current.delegate)
            }
        } catch (_: Exception) {
            // Ignore — SecurityManager cleanup is best-effort
        }
    }

    @Suppress("DEPRECATION")
    private class NextVmSecurityManager(
        val delegate: SecurityManager?
    ) : SecurityManager() {
        override fun checkExit(status: Int) {
            if (isActive()) {
                Timber.tag(TAG).i("Blocked System.exit($status) from guest app")
                throw SecurityException("System.exit blocked by NEXTVM virtual environment")
            }
            delegate?.checkExit(status)
        }

        override fun checkPermission(perm: java.security.Permission?) {
            // Allow everything else
            delegate?.checkPermission(perm)
        }

        override fun checkPermission(perm: java.security.Permission?, context: Any?) {
            delegate?.checkPermission(perm, context)
        }
    }
}
