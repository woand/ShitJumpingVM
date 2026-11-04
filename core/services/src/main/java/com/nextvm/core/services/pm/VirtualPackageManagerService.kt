package com.nextvm.core.services.pm

import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.content.pm.ResolveInfo
import android.content.pm.ServiceInfo
import com.nextvm.core.framework.parsing.ComponentDetail
import com.nextvm.core.framework.parsing.FullPackageInfo
import com.nextvm.core.framework.pkg.VirtualPackageUserState
import com.nextvm.core.model.VirtualApp
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Virtual Package Manager Service — a lightweight real PMS implementation.
 *
 * MODELED ON: android16-frameworks-base/services/core/java/com/android/server/pm/
 *             PackageManagerService.java (8,253 lines)
 *
 * Instead of being a thin proxy that intercepts IPackageManager calls (Phase 1 approach),
 * this is an ACTUAL service implementation that:
 *   - Maintains a registry of installed virtual packages (like PMS's mPackages)
 *   - Resolves intents to virtual components (like PMS's ResolveIntentHelper)
 *   - Tracks per-app user state (like PMS uses PackageSetting/PackageUserState)
 *   - Provides component info queries (getPackageInfo, getActivityInfo, etc.)
 *   - Manages package lifecycle (install, uninstall, update)
 *
 * This replaces Phase 1's PackageManagerProxy InvocationHandler.
 */
@Singleton
class VirtualPackageManagerService @Inject constructor() {

    companion object {
        private const val TAG = "VPMS"
    }

    // ---------- Package Registry (mirrors PMS's mPackages) ----------

    /** All installed virtual packages, keyed by packageName */
    private val packages = ConcurrentHashMap<String, VirtualPackageRecord>()

    /** Maps instanceId → packageName for quick lookup */
    private val instanceToPackage = ConcurrentHashMap<String, String>()

    /** Per-app user state (mirrors PackageUserState in real PMS) */
    private val userStates = ConcurrentHashMap<String, VirtualPackageUserState>()

    // ---------- Package Record (mirrors PMS's PackageSetting) ----------

    data class VirtualPackageRecord(
        val virtualApp: VirtualApp,
        val fullInfo: FullPackageInfo,
        val packageInfo: PackageInfo,
        val activities: List<ComponentDetail>,
        val services: List<ComponentDetail>,
        val providers: List<ComponentDetail>,
        val receivers: List<ComponentDetail>,
        val mainActivity: String?
    )

    // ---------- Registration (called during app install) ----------

    fun registerPackage(app: VirtualApp, fullInfo: FullPackageInfo) {
        val record = VirtualPackageRecord(
            virtualApp = app,
            fullInfo = fullInfo,
            packageInfo = fullInfo.packageInfo,
            activities = fullInfo.activities,
            services = fullInfo.services,
            providers = fullInfo.providers,
            receivers = fullInfo.receivers,
            mainActivity = fullInfo.mainActivity
        )
        packages[app.packageName] = record
        instanceToPackage[app.instanceId] = app.packageName
        userStates[app.packageName] = VirtualPackageUserState(isNotLaunched = true)

        Timber.tag(TAG).i(
            "Registered package: ${app.packageName} " +
            "(${fullInfo.activities.size} activities, " +
            "${fullInfo.services.size} services, " +
            "${fullInfo.providers.size} providers)"
        )
    }

    /**
     * Lightweight registration for apps loaded from disk (no FullPackageInfo available).
     * Creates a minimal record from VirtualApp data only.
     */
    fun registerPackageFromDisk(app: VirtualApp) {
        val packageInfo = PackageInfo().apply {
            packageName = app.packageName
            versionName = app.versionName
            @Suppress("DEPRECATION")
            versionCode = app.versionCode.toInt()
            firstInstallTime = app.installedAt
            lastUpdateTime = app.installedAt
            requestedPermissions = app.requestedPermissions.toTypedArray()
            applicationInfo = buildVirtualApplicationInfo(app)
        }

        val activities = app.activities.map { name ->
            ComponentDetail(
                name = name,
                className = name,
                packageName = app.packageName,
                targetActivity = app.activityAliases[name]
            )
        }

        val applicationInfo = buildVirtualApplicationInfo(app)
        packageInfo.applicationInfo = applicationInfo
        packageInfo.activities = activities.map { detail ->
            ActivityInfo().apply {
                name = detail.name
                packageName = app.packageName
                this.applicationInfo = applicationInfo
            }
        }.toTypedArray()
        packageInfo.services = app.services.map { name ->
            ServiceInfo().apply {
                this.name = name
                packageName = app.packageName
            }
        }.toTypedArray()
        packageInfo.providers = app.providers.map { name ->
            ProviderInfo().apply {
                this.name = name
                packageName = app.packageName
            }
        }.toTypedArray()
        packageInfo.receivers = emptyArray()

        val record = VirtualPackageRecord(
            virtualApp = app,
            fullInfo = FullPackageInfo(
                apkLite = null,
                packageLite = null,
                packageInfo = packageInfo,
                appName = app.appName,
                mainActivity = app.mainActivity,
                applicationClassName = app.applicationClassName,
                activities = activities,
                services = app.services.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
                providers = app.providers.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
                receivers = app.receivers.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
                permissions = app.requestedPermissions
            ),
            packageInfo = packageInfo,
            activities = activities,
            services = app.services.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
            providers = app.providers.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
            receivers = app.receivers.map { ComponentDetail(name = it, className = it, packageName = app.packageName) },
            mainActivity = app.mainActivity
        )
        packages[app.packageName] = record
        instanceToPackage[app.instanceId] = app.packageName
        userStates[app.packageName] = VirtualPackageUserState(isNotLaunched = false)

        Timber.tag(TAG).d("Registered package from disk: ${app.packageName}")
    }

    fun unregisterPackage(packageName: String) {
        val record = packages.remove(packageName)
        if (record != null) {
            instanceToPackage.remove(record.virtualApp.instanceId)
            userStates.remove(packageName)
            Timber.tag(TAG).i("Unregistered package: $packageName")
        }
    }

    // ---------- Package Info Queries (mirrors IPackageManager methods) ----------

    /**
     * Get PackageInfo for a virtual package.
     * Mirrors PMS.getPackageInfo() / Computer.getPackageInfo().
     */
    @Suppress("DEPRECATION")
    fun getPackageInfo(packageName: String, flags: Int = 0): PackageInfo? {
        val record = packages[packageName] ?: return null
        val userState = userStates[packageName] ?: VirtualPackageUserState.DEFAULT
        if (!userState.isInstalled) return null

        return PackageInfo().apply {
            this.packageName = record.packageInfo.packageName
            this.versionName = record.packageInfo.versionName
            this.versionCode = record.packageInfo.versionCode
            this.applicationInfo = getApplicationInfo(packageName, flags)
            this.firstInstallTime = record.virtualApp.installedAt
            this.lastUpdateTime = record.virtualApp.installedAt

            if (flags and PackageManager.GET_ACTIVITIES != 0) {
                this.activities = record.packageInfo.activities
            }
            if (flags and PackageManager.GET_SERVICES != 0) {
                this.services = record.packageInfo.services
            }
            if (flags and PackageManager.GET_PROVIDERS != 0) {
                this.providers = record.packageInfo.providers
            }
            if (flags and PackageManager.GET_RECEIVERS != 0) {
                this.receivers = record.packageInfo.receivers
            }
            if (flags and PackageManager.GET_PERMISSIONS != 0) {
                this.requestedPermissions = record.packageInfo.requestedPermissions
            }
            if (flags and PackageManager.GET_SIGNING_CERTIFICATES != 0) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    this.signingInfo = record.packageInfo.signingInfo
                }
            }
            // v149: legacy GET_SIGNATURES compat. Old SDK code (e.g. CM
            // DeviceInfoUtils.getKeyInfo) reads PackageInfo.signatures[0];
            // the virtual record never filled this deprecated field, so
            // guest callers NPE'd while the real device returns real
            // signatures. Fill from signingInfo when available; the PM
            // proxy adds an APK-parse fallback for disk-registered
            // records, which carry no signingInfo.
            if (flags and PackageManager.GET_SIGNATURES != 0) {
                this.signatures = record.packageInfo.signatures
                    ?: if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                        record.packageInfo.signingInfo?.apkContentsSigners
                    } else {
                        null
                    }
            }
        }
    }

    /**
     * Get ApplicationInfo for a virtual package.
     * Mirrors PMS.getApplicationInfo().
     */
    fun getApplicationInfo(packageName: String, flags: Int = 0): ApplicationInfo? {
        val record = packages[packageName] ?: return null
        val original = record.packageInfo.applicationInfo
            ?: buildVirtualApplicationInfo(record.virtualApp)

        return ApplicationInfo(original).apply {
            this.packageName = record.virtualApp.packageName
            this.sourceDir = record.virtualApp.apkPath
            this.publicSourceDir = record.virtualApp.apkPath
            this.dataDir = record.virtualApp.dataDir
            this.nativeLibraryDir = record.virtualApp.libDir
            this.enabled = true
            this.flags = this.flags or ApplicationInfo.FLAG_INSTALLED or ApplicationInfo.FLAG_HAS_CODE
        }
    }

    /**
     * Get ActivityInfo for a specific activity component.
     * Mirrors PMS.getActivityInfo().
     */
    fun getActivityInfo(componentName: ComponentName, flags: Int = 0): ActivityInfo? {
        val record = packages[componentName.packageName] ?: return null
        val activity = record.activities.find { it.name == componentName.className }
            ?: return null
        return record.packageInfo.activities?.find { it.name == activity.name }
    }

    /**
     * Get ServiceInfo for a specific service component.
     */
    fun getServiceInfo(componentName: ComponentName, flags: Int = 0): ServiceInfo? {
        val record = packages[componentName.packageName] ?: return null
        return record.packageInfo.services?.find { it.name == componentName.className }
    }

    /**
     * Get ProviderInfo for a specific content provider.
     */
    fun getProviderInfo(componentName: ComponentName, flags: Int = 0): ProviderInfo? {
        val record = packages[componentName.packageName] ?: return null
        return record.packageInfo.providers?.find { it.name == componentName.className }
    }

    /**
     * Get the authority string for a ContentProvider by class name.
     */
    fun getProviderAuthority(packageName: String, providerClassName: String): String? {
        val record = packages[packageName] ?: return null
        // Check in PackageInfo.providers
        val providerInfo = record.packageInfo.providers?.find { it.name == providerClassName }
        if (providerInfo?.authority != null) return providerInfo.authority
        // Fallback: check in parsed ComponentDetail
        val detail = record.providers.find { it.className == providerClassName }
        return detail?.authority
    }

    // ---------- Intent Resolution (mirrors PMS's ResolveIntentHelper) ----------

    /**
     * Resolve an intent to the best matching virtual activity.
     * Mirrors PMS/Computer.resolveIntent() and ResolveIntentHelper.
     */
    fun resolveActivity(intent: Intent): ResolveInfo? {
        val results = queryIntentActivities(intent)
        return results.firstOrNull()
    }

    /**
     * Query all virtual activities that match an intent.
     * Mirrors PMS/Computer.queryIntentActivities().
     */
    fun queryIntentActivities(intent: Intent): List<ResolveInfo> {
        val results = mutableListOf<ResolveInfo>()
        val targetPkg = intent.`package` ?: intent.component?.packageName

        for ((pkgName, record) in packages) {
            if (targetPkg != null && pkgName != targetPkg) continue

            val userState = userStates[pkgName] ?: VirtualPackageUserState.DEFAULT
            if (!userState.isInstalled) continue

            // If explicit component, resolve directly
            val component = intent.component
            if (component != null && component.packageName == pkgName) {
                val activity = record.activities.find { it.name == component.className }
                if (activity != null) {
                    val ai = record.packageInfo.activities?.find { it.name == activity.name }
                    if (ai != null) {
                        results.add(ResolveInfo().apply { activityInfo = ai })
                    }
                }
                continue
            }

            // Without a target package, only expose the virtual launchers for
            // the common ACTION_MAIN/CATEGORY_LAUNCHER query. Full implicit
            // intent matching will be added when parsed intent filters are
            // persisted in ComponentDetail.
            val isLauncherQuery = targetPkg == null &&
                intent.action == Intent.ACTION_MAIN &&
                intent.hasCategory(Intent.CATEGORY_LAUNCHER)

            // For package-targeted implicit intents, return the recorded
            // activities. For a global launcher query, return only the app's
            // declared main activity.
            if (targetPkg == pkgName || isLauncherQuery) {
                val activities = if (isLauncherQuery) {
                    val mainName = record.mainActivity
                    record.packageInfo.activities?.filter { ai ->
                        mainName == null || ai.name == mainName
                    }
                } else {
                    record.packageInfo.activities?.toList()
                }
                activities?.forEach { ai ->
                    results.add(ResolveInfo().apply { activityInfo = ai })
                }
            }
        }

        return results
    }

    /**
     * Get all installed virtual packages.
     * Mirrors PMS.getInstalledPackages().
     */
    fun getInstalledPackages(flags: Int = 0): List<PackageInfo> {
        return packages.keys.mapNotNull { getPackageInfo(it, flags) }
    }

    /**
     * Get all installed virtual applications. This is deliberately derived
     * from the same registry as getInstalledPackages() so the two APIs cannot
     * disagree after install, uninstall, or disk reload.
     */
    fun getInstalledApplications(flags: Int = 0): List<ApplicationInfo> {
        return packages.keys.mapNotNull { getApplicationInfo(it, flags) }
    }

    // ---------- Permission Management ----------

    /**
     * Check if a virtual app has a permission.
     * Mirrors PMS.checkPermission().
     */
    fun checkPermission(permName: String, packageName: String): Int {
        val record = packages[packageName] ?: return PackageManager.PERMISSION_DENIED
        val app = record.virtualApp

        val override = app.permissionOverrides[permName]
        if (override != null) {
            return if (override) PackageManager.PERMISSION_GRANTED
                   else PackageManager.PERMISSION_DENIED
        }

        val requested = record.packageInfo.requestedPermissions ?: emptyArray()
        return if (permName in requested) PackageManager.PERMISSION_GRANTED
               else PackageManager.PERMISSION_DENIED
    }

    // ---------- Lookup Helpers ----------

    fun isVirtualPackage(packageName: String): Boolean = packages.containsKey(packageName)
    fun getMainActivity(packageName: String): String? = packages[packageName]?.mainActivity
    fun getRecord(packageName: String): VirtualPackageRecord? = packages[packageName]
    fun getPackageForInstance(instanceId: String): String? = instanceToPackage[instanceId]
    fun getAllPackageNames(): Set<String> = packages.keys.toSet()

    /**
     * Resolve an activity name to its real class, handling activity-aliases.
     * If the activity is an alias (has targetActivity set), returns the target.
     * Otherwise checks the VirtualApp's activityAliases map as a fallback.
     * Returns the original name if no alias mapping exists.
     */
    fun resolveActivityClass(packageName: String, activityName: String): String {
        val record = packages[packageName] ?: return activityName
        // Primary: check ComponentDetail.targetActivity
        val activity = record.activities.find { it.name == activityName }
        val resolved = activity?.targetActivity
        if (resolved != null) return resolved
        // Fallback: check VirtualApp.activityAliases map
        return record.virtualApp.activityAliases[activityName] ?: activityName
    }

    /**
     * Get launch mode for an activity, using ActivityInfo constants from Android 16.
     */
    fun getActivityLaunchMode(packageName: String, activityName: String): Int {
        val record = packages[packageName] ?: return ActivityInfo.LAUNCH_MULTIPLE
        return record.activities.find { it.name == activityName }?.launchMode
            ?: ActivityInfo.LAUNCH_MULTIPLE
    }

    fun markAsLaunched(packageName: String) {
        val current = userStates[packageName] ?: VirtualPackageUserState.DEFAULT
        userStates[packageName] = current.copy(isNotLaunched = false, isStopped = false)
    }

    fun getUserState(packageName: String): VirtualPackageUserState {
        return userStates[packageName] ?: VirtualPackageUserState.DEFAULT
    }

    fun setUserState(packageName: String, state: VirtualPackageUserState) {
        userStates[packageName] = state
    }

    /**
     * Initialize the package manager service with application context.
     */
    fun initialize(context: android.content.Context) {
        Timber.tag(TAG).d("VirtualPackageManagerService initialized")
    }

    private fun buildVirtualApplicationInfo(app: VirtualApp): ApplicationInfo {
        return ApplicationInfo().apply {
            packageName = app.packageName
            sourceDir = app.apkPath
            publicSourceDir = app.apkPath
            dataDir = app.dataDir
            nativeLibraryDir = app.libDir
            processName = app.packageName
            enabled = true
            flags = ApplicationInfo.FLAG_INSTALLED or ApplicationInfo.FLAG_HAS_CODE
        }
    }
}
