package com.nextvm.core.binder.proxy

import android.content.Context
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import android.content.pm.ActivityInfo
import android.content.pm.ResolveInfo
import com.nextvm.core.binder.VirtualCallerResolver
import com.nextvm.core.model.GmsServiceRouter
import com.nextvm.core.model.VirtualApp
import com.nextvm.core.model.VirtualConstants
import com.nextvm.core.services.pm.VirtualPackageManagerService
import timber.log.Timber
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method

/**
 * PackageManagerProxy — Intercepts all IPackageManager IPC calls.
 *
 * Based on Android 16 IPackageManager.aidl analysis:
 * - getPackageInfo: Return virtual package info for installed virtual apps
 * - getApplicationInfo: Return virtual app info
 * - getActivityInfo: Return virtual activity info
 * - resolveIntent: Resolve against virtual component registry
 * - queryIntentActivities: Include virtual app activities
 * - checkPermission: Check against virtual permission policy
 */
class PackageManagerProxy(
    private val original: Any,
    private val context: Context,
    private val virtualPm: VirtualPackageManagerService,
    private val callerResolver: VirtualCallerResolver
) : InvocationHandler {

    companion object {
        private const val TAG = "PMProxy"
        private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

        // PmTrace (v31): record-only tracing of every PM call a guest
        // process makes — method, key arg, flags, and a result summary.
        // Exists to find the synchronous PM query whose answer in the
        // sandbox stalls the guest's init pipeline (splash hang).
        private const val TRACE_MAX = 400
        private val traceCount = java.util.concurrent.atomic.AtomicInteger(0)
        private val WV_PACKAGES = setOf(
            "com.google.android.webview",
            "com.android.webview",
            "com.google.android.gms"
        )
    }

    // Virtual app registry
    private val virtualApps = mutableMapOf<String, VirtualApp>()

    // Cached PackageInfo for virtual apps
    private val packageInfoCache = mutableMapOf<String, PackageInfo>()

    // GMS service router — provides synthesized GMS PackageInfo
    @Volatile
    private var gmsRouter: GmsServiceRouter? = null

    // Re-entrancy guard: prevents StackOverflow when synthesizeGmsPackageInfo calls
    // context.packageManager.getPackageInfo() which loops back into this proxy.
    private val gmsLookupInProgress = ThreadLocal<Boolean>()

    /**
     * Set the GMS service router. Enables returning synthesized
     * PackageInfo for GMS packages (com.google.android.gms, etc.)
     * when guest apps query them via getPackageInfo().
     */
    fun setGmsRouter(router: GmsServiceRouter) {
        gmsRouter = router
        Timber.tag(TAG).i("GMS router connected to PackageManagerProxy")
    }

    fun registerApp(app: VirtualApp) {
        // Package data is registered by VirtualEngine in VirtualPackageManagerService.
        // Keep this callback for BinderProxyManager compatibility, but do not
        // maintain a second PackageInfo registry here.
        Timber.tag(TAG).d("Binder registration observed for ${app.packageName}")
    }

    fun unregisterApp(packageName: String) {
        Timber.tag(TAG).d("Binder unregistration observed for $packageName")
    }

    /**
     * Get theme resource ID for a specific activity.
     * Returns activity-specific theme if set, falls back to application theme.
     */
    fun getActivityTheme(packageName: String, activityName: String): Int {
        val pkgInfo = virtualPm.getPackageInfo(
            packageName,
            PackageManager.GET_ACTIVITIES or PackageManager.GET_META_DATA
        ) ?: return 0
        val ai = pkgInfo.activities?.firstOrNull { it.name == activityName }
        if (ai != null && ai.theme != 0) return ai.theme
        return pkgInfo.applicationInfo?.theme ?: 0
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        // PmTrace (v31): wrap the real dispatch; record-only, never
        // alters arguments, results, or exception behavior.
        val traced = try {
            callerResolver.isGuestProcess()
        } catch (_: Exception) {
            false
        }
        if (traced) tracePmCall(method.name, args, null, -1, null)
        return try {
            val result = invokeDispatch(proxy, method, args)
            if (traced) tracePmCall(method.name, args, result, 0, null)
            result
        } catch (e: Exception) {
            if (traced) tracePmCall(method.name, args, null, 0, e)
            throw e
        }
    }

    private fun invokeDispatch(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val methodName = method.name

        return try {
            when (methodName) {
                "getPackageInfo" -> handleGetPackageInfo(method, args)
                "getApplicationInfo" -> handleGetApplicationInfo(method, args)
                "getActivityInfo" -> handleGetActivityInfo(method, args)
                "resolveIntent" -> handleResolveIntent(method, args)
                "queryIntentActivities" -> handleQueryIntentActivities(method, args)
                "getInstalledPackages" -> handleGetInstalledPackages(method, args)
                "getInstalledApplications" -> handleGetInstalledApplications(method, args)
                "getPackageUid" -> handleGetPackageUid(method, args)
                "checkPermission" -> handleCheckPermission(method, args)
                "checkUidPermission" -> handleCheckUidPermission(method, args)

                // Splash screen APIs — guest app can't own its package at system level.
                // These throw SecurityException ("Calling uid XXXX does not own package")
                // because the virtual app runs under NEXTVM's UID, not its own.
                // Safe to no-op: splash screen theming is not meaningful in virtual env.
                "setSplashScreenTheme",
                "setSplashScreenStyle",
                "reportSplashScreenAttached" -> {
                    Timber.tag(TAG).d("SplashScreen API $methodName no-op for virtual guest (pkg=${args?.getOrNull(0)})")
                    null
                }

                // setComponentEnabledSetting — guest app tries to enable/disable its own
                // components (e.g. WorkManager's SystemJobService) but those components
                // belong to the guest package which isn't actually installed on the system.
                // NEXTVM's UID can't modify another package's components → SecurityException.
                // Safe to silently no-op.
                "setComponentEnabledSetting" -> {
                    Timber.tag(TAG).d("setComponentEnabledSetting no-op for virtual guest (component=${args?.getOrNull(0)})")
                    null
                }

                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in proxy method: $methodName")
            // For SecurityExceptions from virtual app operations, swallow rather than propagate
            val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
            if (cause is SecurityException) {
                Timber.tag(TAG).w("PM SecurityException swallowed for $methodName: ${cause.message}")
                null
            } else if (callerResolver.isGuestProcess() && isGuestIsolatedMethod(methodName)) {
                // Never recover an isolation failure by forwarding the same
                // request to the real PMS; that would leak the main-profile
                // package list after a proxy-side error.
                if (methodName == "getInstalledPackages" ||
                    methodName == "getInstalledApplications" ||
                    methodName == "queryIntentActivities"
                ) {
                    wrapListReturnValue(method.returnType, emptyList<Any>())
                } else {
                    null
                }
            } else {
                invokeOriginal(method, args)
            }
        }
    }

    private fun handleGetPackageInfo(method: Method, args: Array<out Any>?): Any? {
        if (args == null || args.isEmpty()) return invokeOriginal(method, args)

        val packageName = args[0] as? String
        val flags = extractFlags(args, 1)

        // The virtual service is the source of truth for Guest package data.
        if (packageName != null && virtualPm.isVirtualPackage(packageName)) {
            val info = virtualPm.getPackageInfo(packageName, flags)
            Timber.tag(TAG).d("Returning virtual PackageInfo for $packageName")
            return info
        }

        // Do not expose arbitrary main-profile packages to Guest code. System
        // packages are still allowed because Android libraries commonly query
        // them directly, while user-installed host packages remain hidden.
        if (callerResolver.isGuestProcess() && packageName != null) {
            if (isGmsPackage(packageName)) {
                return getGmsPackageInfo(method, args, packageName)
            }
            val realInfo = invokeOriginal(method, args) as? PackageInfo
            return if (realInfo?.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0 ||
                packageName == context.packageName
            ) {
                realInfo
            } else {
                Timber.tag(TAG).d("Hiding host PackageInfo from Guest: $packageName")
                null
            }
        }

        // Check GMS packages — pass through to real PM first (preserves caller's flags
        // like GET_SIGNING_CERTIFICATES needed by GoogleSignatureVerifier), fall back to
        // synthesis only when GMS isn't installed on the host device.
        val router = gmsRouter
        if (packageName != null && router != null && router.isGmsPackage(packageName)
                && gmsLookupInProgress.get() != true) {
            // Try real PM first — preserves caller's flags
            try {
                val realInfo = invokeOriginal(method, args)
                if (realInfo != null) return realInfo
            } catch (_: Exception) {}

            // GMS not installed on host — synthesize
            gmsLookupInProgress.set(true)
            try {
                val gmsInfo = router.synthesizeGmsPackageInfo(packageName)
                if (gmsInfo != null) {
                    Timber.tag(TAG).d("Returning synthesized GMS PackageInfo for $packageName (v=${gmsInfo.versionName})")
                    return gmsInfo
                }
            } finally {
                gmsLookupInProgress.set(false)
            }
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetApplicationInfo(method: Method, args: Array<out Any>?): Any? {
        if (args == null || args.isEmpty()) return invokeOriginal(method, args)

        val packageName = args[0] as? String
        val flags = extractFlags(args, 1)
        if (packageName != null && virtualPm.isVirtualPackage(packageName)) {
            val appInfo = virtualPm.getApplicationInfo(packageName, flags)
            Timber.tag(TAG).d("Returning virtual ApplicationInfo for $packageName")
            return appInfo
        }

        // GMS packages — return applicationInfo from synthesized PackageInfo
        val router = gmsRouter
        if (packageName != null && router != null && router.isGmsPackage(packageName)) {
            val gmsInfo = router.synthesizeGmsPackageInfo(packageName)
            if (gmsInfo?.applicationInfo != null) {
                Timber.tag(TAG).d("Returning synthesized GMS ApplicationInfo for $packageName")
                return gmsInfo.applicationInfo
            }
        }

        if (callerResolver.isGuestProcess() && packageName != null) {
            val realInfo = invokeOriginal(method, args) as? ApplicationInfo
            return if (realInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) != 0 ||
                packageName == context.packageName
            ) {
                realInfo
            } else {
                Timber.tag(TAG).d("Hiding host ApplicationInfo from Guest: $packageName")
                null
            }
        }

        // Host package — inject GMS version metadata so Google Play Services SDKs
        // inside virtual apps don't throw GooglePlayServicesMissingManifestValueException.
        // Many SDKs call context.getPackageName() which returns the host package name,
        // then check getApplicationInfo(hostPkg).metaData for com.google.android.gms.version.
        if (packageName != null && virtualPm.getAllPackageNames().isNotEmpty() &&
            packageName == context.packageName
        ) {
            val result = invokeOriginal(method, args) as? ApplicationInfo
            if (result != null) {
                val meta = result.metaData ?: android.os.Bundle()
                if (!meta.containsKey("com.google.android.gms.version")) {
                    meta.putInt("com.google.android.gms.version", 243431006)
                    result.metaData = meta
                    Timber.tag(TAG).d("Injected GMS version metadata into host ApplicationInfo")
                }
                return result
            }
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetActivityInfo(method: Method, args: Array<out Any>?): Any? {
        val component = args?.firstOrNull { it is ComponentName } as? ComponentName
        if (component != null && virtualPm.isVirtualPackage(component.packageName)) {
            return virtualPm.getActivityInfo(component, extractFlags(args, 1))
        }
        if (callerResolver.isGuestProcess() && component != null &&
            !isSystemPackage(component.packageName) && component.packageName != context.packageName
        ) {
            return null
        }
        return invokeOriginal(method, args)
    }

    private fun handleResolveIntent(method: Method, args: Array<out Any>?): Any? {
        val intent = args?.firstOrNull { it is Intent } as? Intent
        if (callerResolver.isGuestProcess()) {
            return intent?.let { virtualPm.resolveActivity(it) }
        }
        return invokeOriginal(method, args)
    }

    private fun handleQueryIntentActivities(method: Method, args: Array<out Any>?): Any? {
        val intent = args?.firstOrNull { it is Intent } as? Intent
        if (callerResolver.isGuestProcess()) {
            val results = intent?.let { virtualPm.queryIntentActivities(it) } ?: emptyList()
            Timber.tag(TAG).d(
                "Guest queryIntentActivities(${intent?.action}, ${intent?.component}) -> " +
                    results.mapNotNull { it.activityInfo?.packageName }
            )
            return wrapListReturnValue(method.returnType, results)
        }
        return invokeOriginal(method, args)
    }

    private fun handleGetInstalledPackages(method: Method, args: Array<out Any>?): Any? {
        if (callerResolver.isGuestProcess()) {
            val packages = virtualPm.getInstalledPackages(extractFlags(args))
            Timber.tag(TAG).d(
                "Guest getInstalledPackages -> ${packages.mapNotNull { it.packageName }}"
            )
            return wrapListReturnValue(method.returnType, packages)
        }
        return invokeOriginal(method, args)
    }

    private fun handleGetInstalledApplications(method: Method, args: Array<out Any>?): Any? {
        if (callerResolver.isGuestProcess()) {
            val applications = virtualPm.getInstalledApplications(extractFlags(args))
            Timber.tag(TAG).d(
                "Guest getInstalledApplications -> ${applications.map { it.packageName }}"
            )
            return wrapListReturnValue(method.returnType, applications)
        }
        return invokeOriginal(method, args)
    }

    private fun isGmsPackage(packageName: String): Boolean {
        return gmsRouter?.isGmsPackage(packageName) == true
    }

    private fun getGmsPackageInfo(
        method: Method,
        args: Array<out Any>,
        packageName: String
    ): Any? {
        val router = gmsRouter ?: return null
        if (gmsLookupInProgress.get() == true) return null

        try {
            val realInfo = invokeOriginal(method, args)
            if (realInfo != null) return realInfo
        } catch (_: Exception) {
            // Fall through to the synthesized GMS record.
        }

        gmsLookupInProgress.set(true)
        return try {
            router.synthesizeGmsPackageInfo(packageName)?.also {
                Timber.tag(TAG).d(
                    "Returning synthesized GMS PackageInfo for $packageName (v=${it.versionName})"
                )
            }
        } finally {
            gmsLookupInProgress.set(false)
        }
    }

    private fun isSystemPackage(packageName: String): Boolean {
        return packageName == "android" || packageName.startsWith("android.") ||
            packageName.startsWith("com.android.")
    }

    private fun isGuestIsolatedMethod(methodName: String): Boolean {
        return methodName == "getPackageInfo" ||
            methodName == "getApplicationInfo" ||
            methodName == "getActivityInfo" ||
            methodName == "resolveIntent" ||
            methodName == "queryIntentActivities" ||
            methodName == "getInstalledPackages" ||
            methodName == "getInstalledApplications"
    }

    private fun extractFlags(args: Array<out Any>?, startIndex: Int = 0): Int {
        if (args == null) return 0
        return args.drop(startIndex)
            .firstOrNull { it is Number }
            ?.let { (it as Number).toLong().toInt() }
            ?: 0
    }

    /**
     * IPackageManager uses ParceledListSlice on current Android releases,
     * while older releases and test doubles may expose a normal List.
     */
    private fun wrapListReturnValue(returnType: Class<*>, items: List<*>): Any {
        if (returnType.isAssignableFrom(items.javaClass) ||
            java.util.List::class.java.isAssignableFrom(returnType)
        ) {
            return items
        }

        if (returnType.name == "android.content.pm.ParceledListSlice") {
            val constructor = returnType.getConstructor(java.util.List::class.java)
            return constructor.newInstance(items)
        }

        throw IllegalStateException("Unsupported PackageManager list return type: $returnType")
    }

    private fun handleGetPackageUid(method: Method, args: Array<out Any>?): Any? {
        if (args == null || args.isEmpty()) return invokeOriginal(method, args)

        val packageName = args[0] as? String
        val record = packageName?.let { virtualPm.getRecord(it) }
        if (record != null) {
            // Return a virtual UID based on process slot
            val app = record.virtualApp
            val virtualUid = 10000 + app.processSlot + 1000 // Offset to avoid conflicts
            return virtualUid
        }

        return invokeOriginal(method, args)
    }

    private fun handleCheckPermission(method: Method, args: Array<out Any>?): Any? {
        if (args == null || args.size < 2) return invokeOriginal(method, args)

        val permission = args[0] as? String
        val packageName = args[1] as? String

        val record = packageName?.let { virtualPm.getRecord(it) }
        if (record != null) {
            val app = record.virtualApp
            // Check against virtual permission overrides (allow explicit deny)
            val override = app.permissionOverrides[permission]
            if (override != null) {
                return if (override) 0 else -1 // PERMISSION_GRANTED or PERMISSION_DENIED
            }
            // Auto-grant ALL permissions to virtual apps
            return 0 // PackageManager.PERMISSION_GRANTED
        }

        return invokeOriginal(method, args)
    }

    /**
     * Handle checkUidPermission — some framework code checks by UID instead of package name.
     * Since virtual apps run under the host UID, we intercept and return GRANTED
     * for all permission checks that could be coming from a virtual app context.
     *
     * AIDL: int checkUidPermission(String permName, int uid)
     */
    private fun handleCheckUidPermission(method: Method, args: Array<out Any>?): Any? {
        if (args == null || args.size < 2) return invokeOriginal(method, args)

        // If any virtual app is registered, grant permissions for the host UID
        // because all virtual apps run under the host app's UID
        if (virtualPm.getAllPackageNames().isNotEmpty()) {
            val hostUid = android.os.Process.myUid()
            val checkedUid = args[1] as? Int
            if (checkedUid == hostUid) {
                return 0 // PackageManager.PERMISSION_GRANTED
            }
        }

        return invokeOriginal(method, args)
    }

    /**
     * Parse APK manifest directly using AssetManager to build PackageInfo cache.
     * This bypasses PackageParser2 which triggers AconfigFlags static init
     * that crashes on devices missing /vendor/etc/aconfig_flags.pb.
     */
    private fun parseApkDirect(app: VirtualApp) {
        try {
            val am = android.content.res.AssetManager::class.java.getDeclaredConstructor().newInstance()
            val addAssetPath = android.content.res.AssetManager::class.java
                .getDeclaredMethod("addAssetPath", String::class.java)
            addAssetPath.isAccessible = true
            addAssetPath.invoke(am, app.apkPath)

            val parser = am.openXmlResourceParser("AndroidManifest.xml")

            var packageName = app.packageName
            var versionCode = 0L
            var versionName = ""
            val activities = mutableListOf<ActivityInfo>()
            val services = mutableListOf<android.content.pm.ServiceInfo>()
            val providers = mutableListOf<android.content.pm.ProviderInfo>()
            val permissions = mutableListOf<String>()

            var currentActivityName: String? = null
            var currentActivityTheme = 0
            var appThemeResId = 0
            var inActivity = false
            var inIntentFilter = false

            var eventType = parser.eventType
            while (eventType != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                when (eventType) {
                    org.xmlpull.v1.XmlPullParser.START_TAG -> {
                        when (parser.name) {
                            "manifest" -> {
                                packageName = parser.getAttributeValue(null, "package")
                                    ?: app.packageName
                                versionCode = parser.getAttributeValue(ANDROID_NS, "versionCode")
                                    ?.toLongOrNull() ?: 0L
                                versionName = parser.getAttributeValue(ANDROID_NS, "versionName")
                                    ?: ""
                            }
                            "application" -> {
                                appThemeResId = parser.getAttributeResourceValue(ANDROID_NS, "theme", 0)
                            }
                            "activity", "activity-alias" -> {
                                inActivity = true
                                val name = parser.getAttributeValue(ANDROID_NS, "name")
                                currentActivityName = resolveClassName(name, packageName)
                                currentActivityTheme = parser.getAttributeResourceValue(ANDROID_NS, "theme", 0)
                            }
                            "service" -> {
                                val name = parser.getAttributeValue(ANDROID_NS, "name")
                                if (name != null) {
                                    val si = android.content.pm.ServiceInfo()
                                    si.name = resolveClassName(name, packageName)
                                    si.packageName = packageName
                                    services.add(si)
                                }
                            }
                            "provider" -> {
                                val name = parser.getAttributeValue(ANDROID_NS, "name")
                                val authority = parser.getAttributeValue(ANDROID_NS, "authorities")
                                if (name != null) {
                                    val pi = android.content.pm.ProviderInfo()
                                    pi.name = resolveClassName(name, packageName)
                                    pi.packageName = packageName
                                    pi.authority = authority
                                    providers.add(pi)
                                }
                            }
                            "uses-permission" -> {
                                val perm = parser.getAttributeValue(ANDROID_NS, "name")
                                if (perm != null) permissions.add(perm)
                            }
                            "intent-filter" -> {
                                if (inActivity) inIntentFilter = true
                            }
                            "action" -> {
                                if (inIntentFilter) {
                                    // Parsing intent-filter actions (for future MAIN/LAUNCHER detection)
                                }
                            }
                            "category" -> {
                                if (inIntentFilter) {
                                    // Parsing intent-filter categories
                                }
                            }
                        }
                    }
                    org.xmlpull.v1.XmlPullParser.END_TAG -> {
                        when (parser.name) {
                            "activity", "activity-alias" -> {
                                if (currentActivityName != null) {
                                    val ai = ActivityInfo()
                                    ai.name = currentActivityName
                                    ai.packageName = packageName
                                    ai.theme = currentActivityTheme
                                    activities.add(ai)
                                }
                                inActivity = false
                                inIntentFilter = false
                                currentActivityName = null
                                currentActivityTheme = 0
                            }
                            "intent-filter" -> inIntentFilter = false
                        }
                    }
                }
                eventType = parser.next()
            }
            parser.close()
            am.close()

            // Build PackageInfo from parsed data
            val info = PackageInfo()
            info.packageName = packageName
            info.versionName = versionName
            @Suppress("DEPRECATION")
            info.versionCode = versionCode.toInt()

            val appInfo = ApplicationInfo()
            appInfo.packageName = packageName
            appInfo.sourceDir = app.apkPath
            appInfo.publicSourceDir = app.apkPath
            appInfo.dataDir = "${context.filesDir}/${VirtualConstants.VIRTUAL_DIR}/" +
                    "${VirtualConstants.VIRTUAL_DATA_DIR}/${app.instanceId}"
            appInfo.nativeLibraryDir = "${appInfo.dataDir}/lib"
            appInfo.enabled = true
            appInfo.flags = ApplicationInfo.FLAG_INSTALLED
            appInfo.theme = appThemeResId
            info.applicationInfo = appInfo

            // Link each ActivityInfo to applicationInfo so getThemeResource() fallback works
            activities.forEach { it.applicationInfo = appInfo }

            info.activities = activities.toTypedArray()
            info.services = services.toTypedArray()
            info.providers = providers.toTypedArray()
            info.requestedPermissions = permissions.toTypedArray()

            // Extract signing certificates from APK so GMS/Firebase can verify
            // the app's identity (fingerprint hash, GoogleSignatureVerifier, etc.)
            try {
                val archiveInfo = context.packageManager.getPackageArchiveInfo(
                    app.apkPath,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                if (archiveInfo?.signingInfo != null) {
                    info.signingInfo = archiveInfo.signingInfo
                    Timber.tag(TAG).d("parseApkDirect: extracted signingInfo for $packageName")
                } else {
                    // Fallback to deprecated GET_SIGNATURES for older signing schemes
                    @Suppress("DEPRECATION")
                    val archiveLegacy = context.packageManager.getPackageArchiveInfo(
                        app.apkPath,
                        @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
                    )
                    @Suppress("DEPRECATION")
                    if (archiveLegacy?.signatures != null) {
                        @Suppress("DEPRECATION")
                        info.signatures = archiveLegacy.signatures
                        Timber.tag(TAG).d("parseApkDirect: extracted legacy signatures for $packageName")
                    }
                }
            } catch (e: Exception) {
                Timber.tag(TAG).w("Could not extract signing info for $packageName: ${e.message}")
            }

            packageInfoCache[packageName] = info
            Timber.tag(TAG).d("parseApkDirect: cached PackageInfo for $packageName " +
                    "(${activities.size} activities, ${services.size} services)")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "parseApkDirect failed for ${app.packageName}")
        }
    }

    /**
     * Resolve a class name from the manifest. Handles:
     * - ".MyActivity" → "com.pkg.MyActivity" (relative with dot)
     * - "MyActivity" → "com.pkg.MyActivity" (short name, no dot)
     * - "com.pkg.MyActivity" → "com.pkg.MyActivity" (already fully qualified)
     */
    private fun resolveClassName(name: String?, packageName: String): String? {
        if (name == null) return null
        return when {
            name.startsWith(".") -> "$packageName$name"
            !name.contains(".") -> "$packageName.$name"
            else -> name
        }
    }

    private fun buildApplicationInfo(app: VirtualApp): ApplicationInfo {
        return ApplicationInfo().apply {
            packageName = app.packageName
            sourceDir = app.apkPath
            publicSourceDir = app.apkPath
            dataDir = "${context.filesDir}/${VirtualConstants.VIRTUAL_DIR}/${VirtualConstants.VIRTUAL_DATA_DIR}/${app.instanceId}"
            nativeLibraryDir = "$dataDir/lib"
            enabled = true
            flags = ApplicationInfo.FLAG_INSTALLED or ApplicationInfo.FLAG_HAS_CODE

            // Include meta-data from the guest APK so GMS/SDKs can read their
            // <meta-data> tags (com.google.android.gms.version, etc.)
            try {
                val pm = context.packageManager
                val pkgInfo = pm.getPackageArchiveInfo(
                    app.apkPath,
                    android.content.pm.PackageManager.GET_META_DATA
                )
                pkgInfo?.applicationInfo?.let { it2 ->
                    it2.sourceDir = app.apkPath
                    it2.publicSourceDir = app.apkPath
                }
                val bundle = pkgInfo?.applicationInfo?.metaData ?: android.os.Bundle()

                // Inject GMS version if not present — many SDKs crash without this
                if (!bundle.containsKey("com.google.android.gms.version")) {
                    bundle.putInt("com.google.android.gms.version", 243431006)
                }

                this.metaData = bundle
            } catch (e: Exception) {
                Timber.tag(TAG).w("Failed to parse metaData from APK: ${app.apkPath}")
                this.metaData = android.os.Bundle().apply {
                    putInt("com.google.android.gms.version", 243431006)
                }
            }
        }
    }

    // ==================== PmTrace (v31) ====================

    private fun tracePmCall(
        methodName: String,
        args: Array<out Any>?,
        result: Any?,
        phase: Int,
        error: Exception?
    ) {
        try {
            val n = traceCount.incrementAndGet()
            if (n > TRACE_MAX) return
            val sb = StringBuilder()
            // WV> marks queries about WebView/GMS packages — the prime
            // suspects for a silently-missing init dependency.
            val pkgArg = args?.firstOrNull { it is String } as? String
                ?: (args?.firstOrNull { it is ComponentName } as? ComponentName)?.packageName
            if (pkgArg != null && pkgArg in WV_PACKAGES || methodName.contains("WebView")) {
                sb.append("WV> ")
            }
            sb.append(if (phase < 0) ">> " else "<< ").append(methodName)
            if (args != null) {
                for (a in args) {
                    when (a) {
                        is String -> sb.append(" str=").append(a)
                        is ComponentName -> sb.append(" cmp=")
                            .append(a.flattenToShortString())
                        is Intent -> sb.append(" intent{cmp=")
                            .append(a.component?.flattenToShortString())
                            .append(" act=").append(a.action)
                            .append(" pkg=").append(a.`package`).append('}')
                        else -> { /* binder/other objects: skip */ }
                    }
                }
                if (phase < 0) {
                    val flags = extractFlags(args, 1)
                    if (flags != 0) sb.append(" flags=0x").append(flags.toString(16))
                }
            }
            if (phase >= 0) {
                sb.append(" -> ")
                if (error != null) {
                    sb.append('!').append(error.javaClass.simpleName)
                        .append(": ").append(error.message)
                } else {
                    sb.append(summarizePmResult(result))
                }
            }
            Timber.tag("PmTrace").i(sb.toString())
        } catch (_: Exception) {
            // Tracing must never break the proxied call.
        }
    }

    private fun summarizePmResult(result: Any?): String {
        return when (result) {
            null -> "null"
            is Int -> "int=$result"
            is Long -> "long=$result"
            is Boolean -> "bool=$result"
            is String -> "str(len=${result.length})"
            is ComponentName -> "cmp=" + result.flattenToShortString()
            is PackageInfo -> "PackageInfo(${result.packageName})"
            is ApplicationInfo -> "ApplicationInfo(${result.packageName})"
            is ActivityInfo -> "ActivityInfo(${result.packageName}/${result.name})"
            is List<*> -> "List[${result.size}]"
            is Array<*> -> "Array[${result.size}]"
            else -> {
                if (result.javaClass.name == "android.content.pm.ParceledListSlice") {
                    try {
                        val list = result.javaClass
                            .getMethod("getList")
                            .invoke(result) as? List<*>
                        "ParceledListSlice[${list?.size}]"
                    } catch (_: Exception) {
                        result.javaClass.simpleName
                    }
                } else {
                    result.javaClass.simpleName
                }
            }
        }
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args)
        else method.invoke(original)
    }
}
