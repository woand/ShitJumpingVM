package com.nextvm.core.binder.proxy

import android.content.Context
import android.os.Environment
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.common.runSafe
import com.nextvm.core.model.DeviceProfile
import com.nextvm.core.model.NetworkPolicy
import com.nextvm.core.model.VirtualConstants
import timber.log.Timber
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SystemServiceProxyManager — Central manager for ALL system service proxies.
 *
 * Installs Java dynamic proxies on system service singletons via reflection.
 * Each proxy intercepts IPC calls from virtual apps and redirects them
 * through the virtual engine.
 *
 * Installation pattern per service:
 *   1. ServiceManager.getService(name) → IBinder
 *   2. IXxxManager.Stub.asInterface(binder) → original interface
 *   3. Proxy.newProxyInstance() with our InvocationHandler
 *   4. Replace the cached singleton field with our proxy
 */
@Singleton
class SystemServiceProxyManager @Inject constructor() {

    companion object {
        private const val TAG = "SvcProxyMgr"

        // Service names matching Context.XXX_SERVICE constants
        const val SERVICE_NOTIFICATION = "notification"
        const val SERVICE_LOCATION = "location"
        const val SERVICE_TELEPHONY = "phone"
        const val SERVICE_CONNECTIVITY = "connectivity"
        const val SERVICE_ALARM = "alarm"
        const val SERVICE_CLIPBOARD = "clipboard"
        const val SERVICE_ACCOUNT = "account"
        const val SERVICE_WINDOW = "window"
        const val SERVICE_AUDIO = "audio"
        const val SERVICE_JOB_SCHEDULER = "jobscheduler"
        const val SERVICE_CAMERA = "camera"
        const val SERVICE_SENSOR = "sensorservice"
        const val SERVICE_BLUETOOTH = "bluetooth_manager"
        const val SERVICE_WIFI = "wifi"
        const val SERVICE_DOWNLOAD = "download"
        const val SERVICE_STORAGE = "storage"
        const val SERVICE_POWER = "power"
        const val SERVICE_DEVICE_POLICY = "device_policy"
        const val SERVICE_USER = "user"
        const val SERVICE_VIBRATOR = "vibrator"
        const val SERVICE_DISPLAY = "display"
        const val SERVICE_INPUT_METHOD = "input_method"
        const val SERVICE_ACCESSIBILITY = "accessibility"
        const val SERVICE_WALLPAPER = "wallpaper"
        const val SERVICE_MEDIA_SESSION = "media_session"
        const val SERVICE_APP_OPS = "appops"
        const val SERVICE_USAGE_STATS = "usagestats"
        const val SERVICE_NETWORK_STATS = "netstats"
        const val SERVICE_PRINT = "print"
        const val SERVICE_MIDI = "midi"
        const val SERVICE_NSD = "servicediscovery"
        const val SERVICE_SEARCH = "search"
        const val SERVICE_SHORTCUT = "shortcut"
        const val SERVICE_CROSS_PROFILE = "crossprofileapps"
        const val SERVICE_DEVICE_IDENTIFIERS = "device_identifiers_policy"
    }

    // Virtual app tracking
    private val virtualPackages = mutableSetOf<String>()
    private val instanceToPackage = mutableMapOf<String, String>()
    private val packageToSlot = mutableMapOf<String, Int>()

    // GMS router — provides per-instance virtual Google accounts for isolation
    @Volatile
    internal var gmsRouter: com.nextvm.core.model.GmsServiceRouter? = null

    /**
     * Set the GMS router to enable per-instance Google account isolation.
     * Called by VirtualEngine after GMS manager is initialized.
     */
    fun setGmsRouter(router: com.nextvm.core.model.GmsServiceRouter) {
        gmsRouter = router
        Timber.tag(TAG).i("GMS router connected to SystemServiceProxyManager (account isolation enabled)")
    }

    // Device profiles per instance
    private val deviceProfiles = mutableMapOf<String, DeviceProfile>()

    // Network policies per instance
    private val networkPolicies = mutableMapOf<String, NetworkPolicy>()

    // GPS spoofing data per instance: instanceId -> (lat, lng)
    private val spoofedLocations = mutableMapOf<String, Pair<Double, Double>>()

    // Per-app clipboard isolation: instanceId -> ClipData-like storage
    private val clipboardStore = mutableMapOf<String, Any?>()

    // Track installed proxies
    private val installedProxies = mutableSetOf<String>()

    // Original service references
    private val originalServices = mutableMapOf<String, Any>()

    // Proxy handler references
    private val proxyHandlers = mutableMapOf<String, InvocationHandler>()

    // PID to instanceId mapping for identifying virtual callers
    private val pidToInstance = mutableMapOf<Int, String>()

    // Application context for proxy operations (set during installAllProxies)
    private var appContext: Context? = null

    /**
     * Register a virtual app for proxy interception.
     */
    fun registerVirtualApp(
        packageName: String,
        instanceId: String,
        processSlot: Int,
        deviceProfile: DeviceProfile? = null,
        networkPolicy: NetworkPolicy = NetworkPolicy.FULL_ACCESS
    ) {
        virtualPackages.add(packageName)
        instanceToPackage[instanceId] = packageName
        packageToSlot[packageName] = processSlot
        deviceProfile?.let { deviceProfiles[instanceId] = it }
        networkPolicies[instanceId] = networkPolicy
        Timber.tag(TAG).d("Registered virtual app: $packageName (instance=$instanceId, slot=$processSlot)")
    }

    /**
     * Unregister a virtual app.
     */
    fun unregisterVirtualApp(packageName: String, instanceId: String) {
        virtualPackages.remove(packageName)
        instanceToPackage.remove(instanceId)
        packageToSlot.remove(packageName)
        deviceProfiles.remove(instanceId)
        networkPolicies.remove(instanceId)
        spoofedLocations.remove(instanceId)
        clipboardStore.remove(instanceId)
        Timber.tag(TAG).d("Unregistered virtual app: $packageName")
    }

    /**
     * Map a PID to a virtual instance (call when starting a guest process).
     */
    fun registerProcessPid(pid: Int, instanceId: String) {
        pidToInstance[pid] = instanceId
    }

    fun unregisterProcessPid(pid: Int) {
        pidToInstance.remove(pid)
    }

    /**
     * Set spoofed GPS location for a virtual app instance.
     */
    fun setSpoofedLocation(instanceId: String, lat: Double, lng: Double) {
        spoofedLocations[instanceId] = Pair(lat, lng)
    }

    /**
     * Set network policy for a virtual app instance.
     */
    fun setNetworkPolicy(instanceId: String, policy: NetworkPolicy) {
        networkPolicies[instanceId] = policy
    }

    /**
     * Install ALL priority-grouped proxies.
     */
    fun installAllProxies(context: Context) {
        appContext = context
        Timber.tag(TAG).i("Installing system service proxies...")

        // Priority 1 — Must have
        installNotificationProxy(context)
        installLocationProxy(context)
        installTelephonyProxy(context)
        installConnectivityProxy(context)
        installAlarmProxy(context)
        installClipboardProxy(context)
        installAccountProxy(context)

        // Priority 2 — Important
        installWindowProxy(context)
        installAudioProxy(context)
        installJobSchedulerProxy(context)

        // Priority 3 — Extended coverage
        installSensorProxy(context)
        installCameraProxy(context)
        installWifiProxy(context)
        installBluetoothProxy(context)
        installDownloadProxy(context)
        installInputMethodProxy(context)
        installStorageProxy(context)
        installDisplayProxy(context)
        installPowerProxy(context)
        installVibratorProxy(context)
        installUsageStatsProxy(context)
        installKeyguardProxy(context)
        installAppOpsProxy(context)
        installUserManagerProxy(context)

        // Priority 4 — Additional coverage
        installDevicePolicyProxy(context)
        installAccessibilityProxy(context)
        installMediaSessionProxy(context)
        installNetworkStatsProxy(context)
        installShortcutProxy(context)
        installWallpaperProxy(context)

        Timber.tag(TAG).i("Installed ${installedProxies.size} system service proxies")

        // Deferred retry for ALL services that failed (common in child processes
        // where some IBinder entries aren't cached yet at init time)
        val allPossibleServices = listOf<Pair<String, () -> Unit>>(
            SERVICE_STORAGE to { installStorageProxy(context) },
            SERVICE_CAMERA to { installCameraProxy(context) },
            SERVICE_DOWNLOAD to { installDownloadProxy(context) },
            SERVICE_VIBRATOR to { installVibratorProxy(context) },
            SERVICE_POWER to { installPowerProxy(context) },
            SERVICE_DISPLAY to { installDisplayProxy(context) },
            SERVICE_WIFI to { installWifiProxy(context) },
            SERVICE_BLUETOOTH to { installBluetoothProxy(context) },
            SERVICE_INPUT_METHOD to { installInputMethodProxy(context) },
            SERVICE_USAGE_STATS to { installUsageStatsProxy(context) },
            SERVICE_APP_OPS to { installAppOpsProxy(context) },
            SERVICE_USER to { installUserManagerProxy(context) },
        )
        val failedServices = allPossibleServices.filter { (name, _) -> name !in installedProxies }

        if (failedServices.isNotEmpty()) {
            val names = failedServices.map { it.first }
            Timber.tag(TAG).d("Deferred retry scheduled for: $names")
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                for ((name, installer) in failedServices) {
                    if (name !in installedProxies) {
                        try { installer() } catch (e: Exception) {
                            Timber.tag(TAG).w("Deferred retry failed for $name: ${e.message}")
                        }
                    }
                }
                Timber.tag(TAG).d("After deferred retry: ${installedProxies.size} proxies installed")

                // Second retry at 5 seconds for anything still missing
                val stillFailed = failedServices.filter { (name, _) -> name !in installedProxies }
                if (stillFailed.isNotEmpty()) {
                    Timber.tag(TAG).d("Second deferred retry for: ${stillFailed.map { it.first }}")
                    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                        for ((name, installer) in stillFailed) {
                            if (name !in installedProxies) {
                                try { installer() } catch (_: Exception) {}
                            }
                        }
                        Timber.tag(TAG).d("Final proxy count: ${installedProxies.size}")
                    }, 3000L)
                }
            }, 2000L)
        }
    }

    /**
     * Check if the calling PID belongs to a virtual app.
     */
    /**
     * Get the application context for proxy operations.
     */
    fun getAppContext(): Context? = appContext

    /**
     * Get the process slot assigned to a virtual app instance.
     */
    fun getSlotForInstance(instanceId: String): Int? {
        val pkg = instanceToPackage[instanceId] ?: return null
        return packageToSlot[pkg]
    }

    /**
     * Check if the calling PID belongs to a virtual app.
     */
    fun isVirtualCall(callingPid: Int): Boolean {
        return pidToInstance.containsKey(callingPid)
    }

    /**
     * Check if a call originates from a virtual app, using both PID check
     * and argument-based detection. In single-process architecture where all
     * virtual apps share the host PID, the PID check alone isn't sufficient.
     * This also checks if any String argument is a known virtual package name.
     */
    fun isVirtualCallOrArgs(callingPid: Int, args: Array<out Any>?): Boolean {
        if (pidToInstance.containsKey(callingPid)) return true
        if (args == null) return false
        return args.any { it is String && virtualPackages.contains(it) }
    }

    /**
     * Get instance ID for a calling PID.
     */
    fun getInstanceForPid(pid: Int): String? = pidToInstance[pid]

    /**
     * Check if a package is virtual.
     */
    fun isVirtualPackage(packageName: String): Boolean = virtualPackages.contains(packageName)

    /**
     * Get device profile for a specific instance.
     */
    fun getDeviceProfile(instanceId: String): DeviceProfile? = deviceProfiles[instanceId]

    /**
     * Alias for isVirtualCall — used by BaseServiceProxy.
     */
    fun isVirtualApp(callingPid: Int): Boolean = isVirtualCall(callingPid)

    /**
     * Check if any args contain a virtual package name.
     */
    fun hasVirtualPackageInArgs(args: Array<out Any>?): Boolean {
        if (args == null) return false
        return args.any { it is String && virtualPackages.contains(it) }
    }

    // ====================================================================
    // Generic proxy installation via ServiceManager cache
    // ====================================================================

    /**
     * Map our service constants to actual ServiceManager registered names.
     * Context.XXX_SERVICE constants differ from ServiceManager keys for some services.
     */
    private fun resolveServiceManagerName(serviceName: String): String {
        return when (serviceName) {
            SERVICE_STORAGE -> "mount"                  // IStorageManager is registered as "mount"
            SERVICE_CAMERA -> "media.camera"            // ICameraService is registered as "media.camera"
            SERVICE_VIBRATOR -> if (android.os.Build.VERSION.SDK_INT >= 31) "vibrator_manager" else "vibrator"
            SERVICE_APP_OPS -> "appops"
            SERVICE_USAGE_STATS -> "usagestats"
            SERVICE_INPUT_METHOD -> "input_method"
            SERVICE_DISPLAY -> "display"
            SERVICE_POWER -> "power"
            SERVICE_BLUETOOTH -> "bluetooth_manager"
            SERVICE_WIFI -> "wifi"
            else -> serviceName
        }
    }

    /**
     * Force a service to initialize by accessing it via Context, which
     * triggers the system to cache the IBinder in ServiceManager.sCache.
     */
    private fun forceServiceInit(serviceName: String) {
        try {
            val ctx = appContext ?: return
            when (serviceName) {
                SERVICE_STORAGE -> ctx.getSystemService(Context.STORAGE_SERVICE)
                SERVICE_CAMERA -> ctx.getSystemService(Context.CAMERA_SERVICE)
                SERVICE_VIBRATOR -> ctx.getSystemService(Context.VIBRATOR_SERVICE)
                SERVICE_POWER -> ctx.getSystemService(Context.POWER_SERVICE)
                SERVICE_DISPLAY -> ctx.getSystemService(Context.DISPLAY_SERVICE)
                SERVICE_WIFI -> ctx.getSystemService(Context.WIFI_SERVICE)
                SERVICE_BLUETOOTH -> ctx.getSystemService(Context.BLUETOOTH_SERVICE)
                SERVICE_INPUT_METHOD -> ctx.getSystemService(Context.INPUT_METHOD_SERVICE)
                SERVICE_USAGE_STATS -> ctx.getSystemService(Context.USAGE_STATS_SERVICE)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).d("forceServiceInit($serviceName) failed: ${e.message}")
        }
    }

    /**
     * Install a proxy on a service obtained through ServiceManager's sCache.
     * This is the generic approach that works for most services.
     *
     * Installation works by:
     * 1. Getting the real IBinder from ServiceManager
     * 2. Creating an interface proxy via Proxy.newProxyInstance()
     * 3. Creating a ServiceBinderWrapper that returns our proxy from queryLocalInterface()
     * 4. Replacing the entry in ServiceManager.sCache so future Stub.asInterface() calls
     *    return our intercepting proxy instead of the real service.
     */
    private fun installViaServiceManagerCache(
        serviceName: String,
        interfaceClassName: String,
        handler: (original: Any) -> InvocationHandler
    ): Boolean {
        return try {
            val serviceManagerClass = Class.forName("android.os.ServiceManager")

            // Resolve the actual ServiceManager name (may differ from our constant)
            val smName = resolveServiceManagerName(serviceName)

            // Get the IBinder from ServiceManager
            val getServiceMethod = serviceManagerClass.getDeclaredMethod("getService", String::class.java)
            getServiceMethod.isAccessible = true
            var binder = getServiceMethod.invoke(null, smName) as? android.os.IBinder

            // If not available, try forcing initialization via context
            if (binder == null && appContext != null) {
                forceServiceInit(serviceName)
                binder = getServiceMethod.invoke(null, smName) as? android.os.IBinder
            }

            if (binder == null) {
                Timber.tag(TAG).w("Service not available: $serviceName (SM name: $smName)")
                return false
            }

            // Convert IBinder to the AIDL interface via Stub.asInterface()
            val interfaceClass = Class.forName(interfaceClassName)
            val stubClass = Class.forName("$interfaceClassName\$Stub")
            val asInterfaceMethod = stubClass.getDeclaredMethod("asInterface", Class.forName("android.os.IBinder"))
            asInterfaceMethod.isAccessible = true
            val originalService = asInterfaceMethod.invoke(null, binder)
                ?: run {
                    Timber.tag(TAG).w("Could not get interface for: $serviceName")
                    return false
                }

            // Save original
            originalServices[serviceName] = originalService

            // Create handler
            val proxyHandler = handler(originalService)
            proxyHandlers[serviceName] = proxyHandler

            // Create dynamic proxy implementing the AIDL interface
            val proxy = Proxy.newProxyInstance(
                interfaceClass.classLoader,
                arrayOf(interfaceClass),
                proxyHandler
            )

            // Get the interface descriptor for ServiceBinderWrapper
            val descriptor = try {
                val descriptorField = stubClass.getDeclaredField("DESCRIPTOR")
                descriptorField.isAccessible = true
                descriptorField.get(null) as? String ?: interfaceClassName
            } catch (_: Exception) {
                interfaceClassName
            }

            // Create a ServiceBinderWrapper and replace in ServiceManager.sCache
            val binderWrapper = ServiceBinderWrapper(binder, proxy, descriptor)
            val sCacheField = findField(serviceManagerClass, "sCache")
                ?: serviceManagerClass.getDeclaredField("sCache")
            sCacheField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val cache = sCacheField.get(null) as? MutableMap<String, Any?>
            if (cache != null) {
                cache[smName] = binderWrapper
                Timber.tag(TAG).d("Replaced sCache[$smName] with ServiceBinderWrapper")
            } else {
                Timber.tag(TAG).w("ServiceManager.sCache not accessible for $serviceName")
            }

            installedProxies.add(serviceName)
            Timber.tag(TAG).i("Proxy installed for: $serviceName")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install proxy for: $serviceName")
            false
        }
    }

    /**
     * Install proxy via a manager class's private static singleton field.
     * This is the preferred approach for common managers.
     */
    private fun installViaSingleton(
        managerClassName: String,
        singletonFieldName: String,
        interfaceClassName: String,
        serviceName: String,
        handler: (original: Any) -> InvocationHandler
    ): Boolean {
        return try {
            val managerClass = Class.forName(managerClassName)
            val singletonField = findField(managerClass, singletonFieldName)
                ?: run {
                    Timber.tag(TAG).w("Field $singletonFieldName not found on $managerClassName")
                    return false
                }
            singletonField.isAccessible = true
            val singleton = singletonField.get(null)

            if (singleton == null) {
                Timber.tag(TAG).w("Singleton is null for $managerClassName.$singletonFieldName")
                return false
            }

            // Determine if it's an android.util.Singleton or a plain field
            val singletonClassName = singleton::class.java.name
            if (singletonClassName.contains("Singleton")) {
                // It's an android.util.Singleton<T>
                val singletonClass = Class.forName("android.util.Singleton")
                val instanceField = findField(singletonClass, "mInstance")
                    ?: singletonClass.getDeclaredField("mInstance")
                instanceField.isAccessible = true

                // Force initialization
                val getMethod = singletonClass.getDeclaredMethod("get")
                getMethod.isAccessible = true
                val original = getMethod.invoke(singleton)
                    ?: run {
                        Timber.tag(TAG).w("Original service is null for $serviceName")
                        return false
                    }

                originalServices[serviceName] = original

                val proxyHandler = handler(original)
                proxyHandlers[serviceName] = proxyHandler

                val interfaceClass = Class.forName(interfaceClassName)
                val proxy = Proxy.newProxyInstance(
                    interfaceClass.classLoader,
                    arrayOf(interfaceClass),
                    proxyHandler
                )

                instanceField.set(singleton, proxy)
            } else {
                // It's a direct static field reference
                val original = singleton
                originalServices[serviceName] = original

                val proxyHandler = handler(original)
                proxyHandlers[serviceName] = proxyHandler

                val interfaceClass = Class.forName(interfaceClassName)
                val proxy = Proxy.newProxyInstance(
                    interfaceClass.classLoader,
                    arrayOf(interfaceClass),
                    proxyHandler
                )

                singletonField.set(null, proxy)
            }

            installedProxies.add(serviceName)
            Timber.tag(TAG).i("Proxy installed via singleton: $serviceName")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install singleton proxy for: $serviceName")
            false
        }
    }

    /**
     * Install proxy by replacing the service field on a manager obtained from Context.
     */
    private fun installViaManagerField(
        context: Context,
        systemServiceName: String,
        serviceFieldName: String,
        interfaceClassName: String,
        handler: (original: Any) -> InvocationHandler
    ): Boolean {
        return try {
            val manager = context.getSystemService(systemServiceName)
                ?: run {
                    Timber.tag(TAG).w("Manager not available: $systemServiceName")
                    return false
                }

            val managerClass = manager::class.java
            val serviceField = findField(managerClass, serviceFieldName)
                ?: run {
                    Timber.tag(TAG).w("Field $serviceFieldName not found on ${managerClass.name}")
                    return false
                }
            serviceField.isAccessible = true
            val original = serviceField.get(manager)
                ?: run {
                    Timber.tag(TAG).w("Service field is null: $serviceFieldName")
                    return false
                }

            originalServices[systemServiceName] = original

            val proxyHandler = handler(original)
            proxyHandlers[systemServiceName] = proxyHandler

            val interfaceClass = Class.forName(interfaceClassName)
            val proxy = Proxy.newProxyInstance(
                interfaceClass.classLoader,
                arrayOf(interfaceClass),
                proxyHandler
            )

            serviceField.set(manager, proxy)

            installedProxies.add(systemServiceName)
            Timber.tag(TAG).i("Proxy installed via manager field: $systemServiceName")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install proxy via manager: $systemServiceName")
            false
        }
    }

    // ====================================================================
    // Priority 1 — Must-have service proxies
    // ====================================================================

    private fun installNotificationProxy(context: Context) {
        try {
            val nmClass = Class.forName("android.app.NotificationManager")
            val sServiceField = findField(nmClass, "sService")
                ?: run {
                    Timber.tag(TAG).w("NotificationManager.sService field not found")
                    return
                }
            sServiceField.isAccessible = true
            val original = sServiceField.get(null)

            if (original == null) {
                // Force initialization: get the service, then get the internal binder
                val nm = context.getSystemService(Context.NOTIFICATION_SERVICE)
                        as? android.app.NotificationManager
                // On Android 8+, calling getNotificationChannels() forces sService init
                try { nm?.notificationChannels } catch (_: Exception) {}
                val retryOriginal = sServiceField.get(null)
                if (retryOriginal == null) {
                    Timber.tag(TAG).d("NotificationManager.sService deferred — will proxy on first use")
                    // Register for deferred proxy installation
                    deferredProxies["notification"] = Runnable {
                        try {
                            val svc = sServiceField.get(null)
                            if (svc != null) {
                                installNotificationProxyInternal(sServiceField, svc)
                            }
                        } catch (e: Exception) {
                            Timber.tag(TAG).w("Deferred notification proxy failed: ${e.message}")
                        }
                    }
                    return
                }
                installNotificationProxyInternal(sServiceField, retryOriginal)
            } else {
                installNotificationProxyInternal(sServiceField, original)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install NotificationManager proxy")
        }
    }

    /** Deferred proxy installations for services that lazy-init their binders */
    private val deferredProxies = mutableMapOf<String, Runnable>()

    /**
     * Try to install any deferred proxies. Should be called periodically
     * or when a virtual app first starts.
     */
    fun installDeferredProxies() {
        val iterator = deferredProxies.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            try {
                entry.value.run()
                iterator.remove()
            } catch (_: Exception) {}
        }
    }

    private fun installNotificationProxyInternal(field: java.lang.reflect.Field, original: Any) {
        originalServices[SERVICE_NOTIFICATION] = original
        val handler = NotificationManagerProxyHandler(original, this)
        proxyHandlers[SERVICE_NOTIFICATION] = handler

        val interfaceClass = Class.forName("android.app.INotificationManager")
        val proxy = Proxy.newProxyInstance(
            interfaceClass.classLoader,
            arrayOf(interfaceClass),
            handler
        )
        field.set(null, proxy)
        installedProxies.add(SERVICE_NOTIFICATION)
        Timber.tag(TAG).i("NotificationManager proxy installed")
    }

    private fun installLocationProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.LOCATION_SERVICE,
            serviceFieldName = "mService",
            interfaceClassName = "android.location.ILocationManager",
            handler = { original -> LocationManagerProxyHandler(original, this) }
        )
    }

    private fun installTelephonyProxy(context: Context) {
        try {
            // Try static field first (may not exist on all Android versions)
            val tmClass = Class.forName("android.telephony.TelephonyManager")
            val sServiceField = try {
                findField(tmClass, "sITelephony")?.also { it.isAccessible = true }
            } catch (_: Exception) {
                null // Field removed in newer Android versions
            }

            val original = sServiceField?.get(null)
            if (original != null) {
                originalServices[SERVICE_TELEPHONY] = original
                val handler = TelephonyManagerProxyHandler(original, this)
                proxyHandlers[SERVICE_TELEPHONY] = handler

                val interfaceClass = Class.forName("com.android.internal.telephony.ITelephony")
                val proxy = Proxy.newProxyInstance(
                    interfaceClass.classLoader,
                    arrayOf(interfaceClass),
                    handler
                )
                sServiceField!!.set(null, proxy)
                installedProxies.add(SERVICE_TELEPHONY)
                Timber.tag(TAG).i("TelephonyManager proxy installed")
            } else {
                // Static field unavailable or null — try ServiceManager cache
                installViaServiceManagerCache(
                    serviceName = SERVICE_TELEPHONY,
                    interfaceClassName = "com.android.internal.telephony.ITelephony",
                    handler = { orig -> TelephonyManagerProxyHandler(orig, this) }
                )
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install TelephonyManager proxy")
        }
    }

    private fun installConnectivityProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.CONNECTIVITY_SERVICE,
            serviceFieldName = "mService",
            interfaceClassName = "android.net.IConnectivityManager",
            handler = { original -> ConnectivityManagerProxyHandler(original, this) }
        )
    }

    private fun installAlarmProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.ALARM_SERVICE,
            serviceFieldName = "mService",
            interfaceClassName = "android.app.IAlarmManager",
            handler = { original -> AlarmManagerProxyHandler(original, this) }
        )
    }

    private fun installClipboardProxy(context: Context) {
        try {
            val cbClass = Class.forName("android.content.ClipboardManager")
            val manager = context.getSystemService(Context.CLIPBOARD_SERVICE)
            if (manager != null) {
                val serviceField = findField(manager::class.java, "mService")
                if (serviceField != null) {
                    serviceField.isAccessible = true
                    val original = serviceField.get(manager)
                    if (original != null) {
                        originalServices[SERVICE_CLIPBOARD] = original
                        val handler = ClipboardManagerProxyHandler(original, this)
                        proxyHandlers[SERVICE_CLIPBOARD] = handler

                        val interfaceClass = Class.forName("android.content.IClipboard")
                        val proxy = Proxy.newProxyInstance(
                            interfaceClass.classLoader,
                            arrayOf(interfaceClass),
                            handler
                        )
                        serviceField.set(manager, proxy)
                        installedProxies.add(SERVICE_CLIPBOARD)
                        Timber.tag(TAG).i("ClipboardManager proxy installed")
                    }
                }
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install ClipboardManager proxy")
        }
    }

    private fun installAccountProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.ACCOUNT_SERVICE,
            serviceFieldName = "mService",
            interfaceClassName = "android.accounts.IAccountManager",
            handler = { original -> AccountManagerProxyHandler(original, this) }
        )
    }

    // ====================================================================
    // Priority 2 — Important service proxies
    // ====================================================================

    private fun installWindowProxy(context: Context) {
        try {
            val wmgClass = Class.forName("android.view.WindowManagerGlobal")
            val getInstanceMethod = wmgClass.getDeclaredMethod("getInstance")
            getInstanceMethod.isAccessible = true
            val instance = getInstanceMethod.invoke(null)

            if (instance != null) {
                val serviceField = findField(wmgClass, "mWindowManagerService")
                    ?: findField(wmgClass, "sWindowManagerService")
                if (serviceField != null) {
                    serviceField.isAccessible = true
                    val original = serviceField.get(instance)
                    if (original != null) {
                        originalServices[SERVICE_WINDOW] = original
                        val handler = WindowManagerProxyHandler(original, this)
                        proxyHandlers[SERVICE_WINDOW] = handler

                        val interfaceClass = Class.forName("android.view.IWindowManager")
                        val proxy = Proxy.newProxyInstance(
                            interfaceClass.classLoader,
                            arrayOf(interfaceClass),
                            handler
                        )
                        serviceField.set(instance, proxy)
                        installedProxies.add(SERVICE_WINDOW)
                        Timber.tag(TAG).i("WindowManager proxy installed")
                    }
                }
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to install WindowManager proxy")
        }
    }

    private fun installAudioProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.AUDIO_SERVICE,
            serviceFieldName = "mAudioService",
            interfaceClassName = "android.media.IAudioService",
            handler = { original -> AudioManagerProxyHandler(original, this) }
        )
    }

    private fun installJobSchedulerProxy(context: Context) {
        installViaManagerField(
            context = context,
            systemServiceName = Context.JOB_SCHEDULER_SERVICE,
            serviceFieldName = "mBinder",
            interfaceClassName = "android.app.job.IJobScheduler",
            handler = { original -> JobSchedulerProxyHandler(original, this) }
        )
    }

    /**
     * Get the device profile for a calling PID's instance.
     */
    internal fun getDeviceProfileForPid(pid: Int): DeviceProfile? {
        val instanceId = pidToInstance[pid] ?: return null
        return deviceProfiles[instanceId]
    }

    /**
     * Get the network policy for a calling PID's instance.
     */
    internal fun getNetworkPolicyForPid(pid: Int): NetworkPolicy? {
        val instanceId = pidToInstance[pid] ?: return null
        return networkPolicies[instanceId]
    }

    /**
     * Get the spoofed location for a calling PID's instance.
     */
    internal fun getSpoofedLocationForPid(pid: Int): Pair<Double, Double>? {
        val instanceId = pidToInstance[pid] ?: return null
        return spoofedLocations[instanceId]
    }

    /**
     * Get the clipboard store for an instance.
     */
    internal fun getClipForInstance(instanceId: String): Any? = clipboardStore[instanceId]

    /**
     * Set the clipboard for an instance.
     */
    internal fun setClipForInstance(instanceId: String, clip: Any?) {
        clipboardStore[instanceId] = clip
    }

    /**
     * Rewrite a package name in method arguments.
     * If the package is one of our virtual packages, replace it with the host package.
     */
    internal fun rewritePackageName(packageName: String?): String {
        if (packageName == null) return VirtualConstants.HOST_PACKAGE
        return if (virtualPackages.contains(packageName)) {
            VirtualConstants.HOST_PACKAGE
        } else {
            packageName
        }
    }

// ========================================================================
// InvocationHandler implementations for each service proxy
// ========================================================================

/**
 * Notification Manager Proxy — intercepts notification-related IPC.
 *
 * Key methods:
 * - enqueueNotificationWithTag: Rewrite package name so system accepts it
 * - cancelNotificationWithTag: Route to correct virtual notification
 * - areNotificationsEnabled: Return true for virtual apps
 * - createNotificationChannel: Prefix channel ID with instanceId
 * - getNotificationChannels: Filter to virtual app's channels
 */
internal class NotificationManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "NMProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "enqueueNotificationWithTag" -> handleEnqueueNotification(method, args, isVirtual)
                "cancelNotificationWithTag" -> handleCancelNotification(method, args, isVirtual)
                "areNotificationsEnabled" -> handleAreNotificationsEnabled(method, args, isVirtual)
                "areNotificationsEnabledForPackage" -> handleAreNotificationsEnabled(method, args, isVirtual)
                "createNotificationChannels" -> handleCreateNotificationChannels(method, args, isVirtual)
                "createNotificationChannelGroups" -> invokeOriginalSafe(method, args)
                "getNotificationChannels",
                "getNotificationChannelsForPackage" -> handleGetNotificationChannels(method, args, isVirtual)
                "getActiveNotifications" -> handleGetActiveNotifications(method, args, isVirtual)
                "cancelAllNotifications" -> handleCancelAllNotifications(method, args, isVirtual)
                else -> invokeOriginalSafe(method, args)
            }
        } catch (e: Exception) {
            val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
            if (cause is SecurityException) {
                Timber.tag(TAG).d("SecurityException suppressed in ${method.name}: ${cause.message}")
                getDefaultReturnValue(method)
            } else {
                Timber.tag(TAG).e(e, "Error in ${method.name}")
                invokeOriginalSafe(method, args)
            }
        }
    }

    /**
     * Check if any String argument is a known virtual package.
     * Invoke original method, rewriting virtual package args to host package first.
     * Prevents SecurityExceptions from package/UID mismatch.
     */
    private fun invokeOriginalSafe(method: Method, args: Array<out Any>?): Any? {
        if (args == null) return method.invoke(original)
        val newArgs = args.toMutableList().toTypedArray()
        for (i in newArgs.indices) {
            if (newArgs[i] is String && manager.isVirtualPackage(newArgs[i] as String)) {
                newArgs[i] = VirtualConstants.HOST_PACKAGE
            }
        }
        return method.invoke(original, *newArgs)
    }

    private fun getDefaultReturnValue(method: Method): Any? {
        return when (method.returnType) {
            Boolean::class.java, java.lang.Boolean::class.java -> true
            Int::class.java, java.lang.Integer::class.java -> 0
            else -> null
        }
    }

    private fun handleEnqueueNotification(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginalSafe(method, args)

        // enqueueNotificationWithTag(String pkg, String opPkg, String tag, int id, Notification n, int userId)
        // Rewrite pkg (arg[0]) and opPkg (arg[1]) to host package
        val newArgs = args.toMutableList().toTypedArray()
        if (args.isNotEmpty() && args[0] is String) {
            val virtualPkg = args[0] as String
            if (manager.isVirtualPackage(virtualPkg)) {
                newArgs[0] = VirtualConstants.HOST_PACKAGE
                Timber.tag(TAG).d("Rewrote notification pkg: $virtualPkg -> ${VirtualConstants.HOST_PACKAGE}")
            }
        }
        if (args.size > 1 && args[1] is String) {
            val opPkg = args[1] as String
            if (manager.isVirtualPackage(opPkg)) {
                newArgs[1] = VirtualConstants.HOST_PACKAGE
            }
        }
        // Prefix the tag with the virtual package for isolation
        if (args.size > 2 && args[2] is String?) {
            val originalTag = args[2] as? String ?: ""
            val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
            newArgs[2] = "${instanceId ?: "v"}_$originalTag"
        }

        return method.invoke(original, *newArgs)
    }

    private fun handleCancelNotification(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginalSafe(method, args)

        val newArgs = args.toMutableList().toTypedArray()
        // Rewrite package name
        if (args.isNotEmpty() && args[0] is String) {
            val pkg = args[0] as String
            if (manager.isVirtualPackage(pkg)) {
                newArgs[0] = VirtualConstants.HOST_PACKAGE
            }
        }
        // Prefix tag
        if (args.size > 1 && args[1] is String?) {
            val tag = args[1] as? String ?: ""
            val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
            newArgs[1] = "${instanceId ?: "v"}_$tag"
        }

        return method.invoke(original, *newArgs)
    }

    private fun handleAreNotificationsEnabled(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginalSafe(method, args)
        // Always report notifications as enabled for virtual apps
        return true
    }

    private fun handleCreateNotificationChannels(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginalSafe(method, args)

        val newArgs = args.toMutableList().toTypedArray()
        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())

        // Rewrite package name in first arg
        if (args.isNotEmpty() && args[0] is String) {
            val pkg = args[0] as String
            if (manager.isVirtualPackage(pkg)) {
                newArgs[0] = VirtualConstants.HOST_PACKAGE
            }
        }

        // Prefix channel IDs with instanceId to isolate between clones
        if (instanceId != null && args.size > 1) {
            try {
                val parceledListSlice = args[1]
                val getListMethod = parceledListSlice::class.java.getMethod("getList")
                val channels = getListMethod.invoke(parceledListSlice) as? List<*>
                channels?.forEach { channel ->
                    if (channel != null) {
                        try {
                            val idField = findField(channel::class.java, "mId")
                                ?: channel::class.java.getDeclaredField("mId")
                            idField.isAccessible = true
                            val originalId = idField.get(channel) as? String ?: return@forEach
                            if (!originalId.startsWith("${instanceId}_")) {
                                idField.set(channel, "${instanceId}_${originalId}")
                                Timber.tag(TAG).d("Prefixed channel ID: $originalId -> ${instanceId}_$originalId")
                            }
                        } catch (_: Exception) { /* Channel ID field not accessible */ }
                    }
                }
            } catch (e: Exception) {
                Timber.tag(TAG).w("Failed to prefix notification channel IDs: ${e.message}")
            }
        }

        return method.invoke(original, *newArgs)
    }

    private fun handleGetNotificationChannels(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginalSafe(method, args)

        val newArgs = args.toMutableList().toTypedArray()
        if (args.isNotEmpty() && args[0] is String) {
            val pkg = args[0] as String
            if (manager.isVirtualPackage(pkg)) {
                newArgs[0] = VirtualConstants.HOST_PACKAGE
            }
        }

        return method.invoke(original, *newArgs)
    }

    private fun handleGetActiveNotifications(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginalSafe(method, args)

        val newArgs = if (args != null) {
            val mutArgs = args.toMutableList().toTypedArray()
            if (mutArgs.isNotEmpty() && mutArgs[0] is String) {
                val pkg = mutArgs[0] as String
                if (manager.isVirtualPackage(pkg)) {
                    mutArgs[0] = VirtualConstants.HOST_PACKAGE
                }
            }
            mutArgs
        } else args

        return method.invoke(original, *(newArgs ?: emptyArray()))
    }

    private fun handleCancelAllNotifications(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginalSafe(method, args)

        val newArgs = args.toMutableList().toTypedArray()
        if (args.isNotEmpty() && args[0] is String) {
            val pkg = args[0] as String
            if (manager.isVirtualPackage(pkg)) {
                newArgs[0] = VirtualConstants.HOST_PACKAGE
            }
        }
        return try {
            method.invoke(original, *newArgs)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            if (e.cause is SecurityException) {
                // NEXTVM's UID doesn't own the guest package — swallow silently.
                Timber.tag(TAG).d("cancelAllNotifications SecurityException suppressed: ${e.cause?.message}")
                null
            } else throw e
        }
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Location Manager Proxy — intercepts location service calls.
 *
 * Key methods:
 * - getLastLocation: Return spoofed GPS if configured
 * - requestLocationUpdates: Provide mock locations
 * - getProviders: Return available providers
 * - isProviderEnabled: Report GPS/network enabled status
 */
internal class LocationManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "LocProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "getLastLocation" -> handleGetLastLocation(method, args, isVirtual)
                "getLastKnownLocation" -> handleGetLastLocation(method, args, isVirtual)
                "requestLocationUpdates" -> handleRequestLocationUpdates(method, args, isVirtual)
                "removeUpdates" -> invokeOriginal(method, args)
                "getProviders" -> handleGetProviders(method, args, isVirtual)
                "getAllProviders" -> handleGetProviders(method, args, isVirtual)
                "isProviderEnabled",
                "isProviderEnabledForUser" -> handleIsProviderEnabled(method, args, isVirtual)
                "getBestProvider" -> handleGetBestProvider(method, args, isVirtual)
                "getGnssYearOfHardware" -> if (isVirtual) 2024 else invokeOriginal(method, args)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleGetLastLocation(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val spoofedLoc = manager.getSpoofedLocationForPid(android.os.Process.myPid())
        if (spoofedLoc != null) {
            val location = createMockLocation(spoofedLoc.first, spoofedLoc.second)
            Timber.tag(TAG).d("Returning spoofed location: ${spoofedLoc.first}, ${spoofedLoc.second}")
            return location
        }

        return invokeOriginal(method, args)
    }

    private fun handleRequestLocationUpdates(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        // If we have spoofed location, intercept and provide mock updates
        val spoofedLoc = manager.getSpoofedLocationForPid(android.os.Process.myPid())
        if (spoofedLoc != null) {
            Timber.tag(TAG).d("Intercepting location updates for virtual app (spoofed GPS active)")
            // Still register with real system to avoid ANR, but listener will get our mock data
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetProviders(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        // Return standard providers
        return listOf("gps", "network", "passive")
    }

    private fun handleIsProviderEnabled(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        // Report all providers enabled for virtual apps
        return true
    }

    private fun handleGetBestProvider(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        return "gps"
    }

    private fun createMockLocation(lat: Double, lng: Double): Any {
        val locationClass = Class.forName("android.location.Location")
        val location = locationClass.getConstructor(String::class.java).newInstance("gps")

        locationClass.getDeclaredMethod("setLatitude", Double::class.javaPrimitiveType).invoke(location, lat)
        locationClass.getDeclaredMethod("setLongitude", Double::class.javaPrimitiveType).invoke(location, lng)
        locationClass.getDeclaredMethod("setAccuracy", Float::class.javaPrimitiveType).invoke(location, 3.0f)
        locationClass.getDeclaredMethod("setTime", Long::class.javaPrimitiveType).invoke(location, System.currentTimeMillis())

        try {
            locationClass.getDeclaredMethod("setElapsedRealtimeNanos", Long::class.javaPrimitiveType)
                .invoke(location, android.os.SystemClock.elapsedRealtimeNanos())
        } catch (_: Exception) { /* OK on older APIs */ }

        locationClass.getDeclaredMethod("setAltitude", Double::class.javaPrimitiveType).invoke(location, 0.0)
        locationClass.getDeclaredMethod("setBearing", Float::class.javaPrimitiveType).invoke(location, 0.0f)
        locationClass.getDeclaredMethod("setSpeed", Float::class.javaPrimitiveType).invoke(location, 0.0f)

        return location
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Telephony Manager Proxy — intercepts telephony identity and status calls.
 *
 * Key methods:
 * - getDeviceId/getImei: Return spoofed IMEI
 * - getSubscriberId: Return spoofed IMSI
 * - getLine1Number: Return spoofed phone number
 * - getSimOperatorName/getNetworkOperatorName: Return spoofed carrier
 * - getSimState: Report ready
 */
internal class TelephonyManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "TelProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        // SvcTrace (v31): record-only wrapper; see svcTrace above.
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)
        if (isVirtual) svcTrace("telephony", method.name, true, null, args, null, -1, null)
        val result = invokeDispatch(proxy, method, args, isVirtual)
        if (isVirtual) svcTrace("telephony", method.name, true, null, args, result, 0, null)
        return result
    }

    private fun invokeDispatch(proxy: Any, method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        return try {
            when (method.name) {
                "getDeviceId",
                "getDeviceIdForPhone" -> handleGetDeviceId(method, args, isVirtual)
                "getImeiForSlot",
                "getImei" -> handleGetImei(method, args, isVirtual)
                "getSubscriberId",
                "getSubscriberIdForSubscriber" -> handleGetSubscriberId(method, args, isVirtual)
                "getLine1Number",
                "getLine1NumberForDisplay" -> handleGetLineNumber(method, args, isVirtual)
                "getSimOperatorName",
                "getSimOperatorNameForPhone" -> handleGetSimOperator(method, args, isVirtual)
                "getNetworkOperatorName",
                "getNetworkOperatorNameForPhone" -> handleGetNetworkOperator(method, args, isVirtual)
                "getSimSerialNumber" -> handleGetSimSerial(method, args, isVirtual)
                "getSimState",
                "getSimStateForSlotIndex" -> handleGetSimState(method, args, isVirtual)
                "getMeid",
                "getMeidForSlot" -> handleGetMeid(method, args, isVirtual)
                "getNetworkType",
                "getDataNetworkType",
                "getDataNetworkTypeForSubscriber",
                "getNetworkTypeForSubscriber" -> handleGetNetworkType(method, args, isVirtual)
                "getPhoneType" -> if (isVirtual) 1 /* GSM */ else invokeOriginal(method, args)
                else -> invokeOriginal(method, args)
            }
        } catch (e: SecurityException) {
            // UID/package security mismatch — return safe defaults for virtual calls
            Timber.tag(TAG).w("SecurityException in ${method.name}: ${e.message}")
            getDefaultForMethod(method.name)
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            getDefaultForMethod(method.name)
        }
    }

    private fun getDefaultForMethod(methodName: String): Any? {
        return when {
            methodName.contains("NetworkType", ignoreCase = true) -> 13 // LTE
            methodName.contains("SimState", ignoreCase = true) -> 5 // SIM_STATE_READY
            methodName.contains("PhoneType", ignoreCase = true) -> 1 // GSM
            else -> null
        }
    }

    private fun handleGetDeviceId(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return profile?.imei?.ifEmpty { generateFakeImei() } ?: invokeOriginal(method, args)
    }

    private fun handleGetImei(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return profile?.imei?.ifEmpty { generateFakeImei() } ?: invokeOriginal(method, args)
    }

    private fun handleGetSubscriberId(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        val mcc = profile?.mcc ?: "310"
        val mnc = profile?.mnc ?: "260"
        return "${mcc}${mnc}${generateConsistentDigits(profile?.serial ?: "default", 10)}"
    }

    private fun handleGetLineNumber(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return if (profile?.carrierName?.isNotEmpty() == true) {
            "+1${generateConsistentDigits(profile.serial, 10)}"
        } else {
            ""
        }
    }

    private fun handleGetSimOperator(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return profile?.carrierName?.ifEmpty { null } ?: invokeOriginal(method, args)
    }

    private fun handleGetNetworkOperator(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return profile?.carrierName?.ifEmpty { null } ?: invokeOriginal(method, args)
    }

    private fun handleGetSimSerial(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return generateConsistentDigits(profile?.serial ?: "simserial", 20)
    }

    private fun handleGetSimState(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        // SIM_STATE_READY = 5
        return 5
    }

    private fun handleGetMeid(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        val profile = manager.getDeviceProfileForPid(android.os.Process.myPid())
        return generateConsistentDigits(profile?.serial ?: "meid", 14)
    }

    private fun handleGetNetworkType(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        // NETWORK_TYPE_LTE = 13
        return 13
    }

    private fun generateFakeImei(): String {
        // Deterministic 15-digit IMEI with valid Luhn check
        val base = "35${generateConsistentDigits("imei_default", 12)}"
        return base.take(14) + luhnCheckDigit(base.take(14))
    }

    private fun generateConsistentDigits(seed: String, length: Int): String {
        val hash = seed.hashCode().toLong().let { if (it < 0) -it else it }
        val sb = StringBuilder()
        var value = hash
        for (i in 0 until length) {
            sb.append((value % 10).toInt())
            value = value / 10 + hash * (i + 1)
            if (value < 0) value = -value
        }
        return sb.toString().take(length)
    }

    private fun luhnCheckDigit(number: String): Char {
        var sum = 0
        var alternate = true
        for (i in number.length - 1 downTo 0) {
            var n = number[i] - '0'
            if (alternate) {
                n *= 2
                if (n > 9) n -= 9
            }
            sum += n
            alternate = !alternate
        }
        return ((10 - (sum % 10)) % 10 + '0'.code).toChar()
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Connectivity Manager Proxy — intercepts network connectivity queries.
 *
 * Key methods:
 * - getActiveNetworkInfo: Filter based on network policy
 * - getNetworkCapabilities: Report based on policy
 * - registerNetworkCallback: Intercept for per-app control
 */
internal class ConnectivityManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "ConnProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        // SvcTrace (v31): record-only wrapper; the instance's network
        // policy rides along because an OFFLINE misjudgment makes the
        // dispatched handlers below return null / swallow callbacks —
        // a prime suspect for the guest's never-satisfied init gate.
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)
        val policy = if (isVirtual) {
            manager.getNetworkPolicyForPid(callingPid)?.toString()
        } else {
            null
        }
        if (isVirtual) svcTrace("connectivity", method.name, true, policy, args, null, -1, null)
        val result = invokeDispatch(proxy, method, args, isVirtual)
        if (isVirtual) svcTrace("connectivity", method.name, true, policy, args, result, 0, null)
        return result
    }

    private fun invokeDispatch(proxy: Any, method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        return try {
            when (method.name) {
                "getActiveNetworkInfo" -> handleGetActiveNetworkInfo(method, args, isVirtual)
                "getActiveNetwork" -> handleGetActiveNetwork(method, args, isVirtual)
                "getNetworkCapabilities" -> handleGetNetworkCapabilities(method, args, isVirtual)
                "getAllNetworkInfo" -> handleGetAllNetworkInfo(method, args, isVirtual)
                "isActiveNetworkMetered" -> handleIsMetered(method, args, isVirtual)
                "registerNetworkCallback" -> handleRegisterCallback(method, args, isVirtual)
                "unregisterNetworkCallback" -> invokeOriginal(method, args)
                "getNetworkInfo" -> handleGetNetworkInfo(method, args, isVirtual)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleGetActiveNetworkInfo(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            Timber.tag(TAG).d("Returning null NetworkInfo for OFFLINE virtual app")
            return null
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetActiveNetwork(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            return null
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetNetworkCapabilities(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            return null
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetAllNetworkInfo(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            return emptyArray<Any>()
        }

        return invokeOriginal(method, args)
    }

    private fun handleIsMetered(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        return invokeOriginal(method, args)
    }

    private fun handleRegisterCallback(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            Timber.tag(TAG).d("Blocking network callback registration for OFFLINE app")
            return null
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetNetworkInfo(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val policy = manager.getNetworkPolicyForPid(android.os.Process.myPid())
        if (policy == NetworkPolicy.OFFLINE) {
            return null
        }

        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Alarm Manager Proxy — isolates alarms per virtual app.
 *
 * Key methods:
 * - set/setExact/setRepeating: Tag with instanceId for routing
 * - cancel: Cancel only this instance's alarms
 */
internal class AlarmManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "AlarmProxy"
    }

    // Track alarms per instance: instanceId -> list of PendingIntent hashcodes
    private val trackedAlarms = mutableMapOf<String, MutableSet<Int>>()

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "set" -> handleSetAlarm(method, args, isVirtual)
                "setExact" -> handleSetAlarm(method, args, isVirtual)
                "setRepeating" -> handleSetAlarm(method, args, isVirtual)
                "setWindow" -> handleSetAlarm(method, args, isVirtual)
                "setInexactRepeating" -> handleSetAlarm(method, args, isVirtual)
                "setAndAllowWhileIdle" -> handleSetAlarm(method, args, isVirtual)
                "setExactAndAllowWhileIdle" -> handleSetAlarm(method, args, isVirtual)
                "cancel" -> handleCancelAlarm(method, args, isVirtual)
                "getNextAlarmClock" -> handleGetNextAlarm(method, args, isVirtual)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleSetAlarm(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            // Track the PendingIntent for later cancellation
            val piArg = args.lastOrNull()
            if (piArg != null) {
                trackedAlarms.getOrPut(instanceId) { mutableSetOf() }.add(System.identityHashCode(piArg))
            }
            Timber.tag(TAG).d("Virtual alarm set for instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun handleCancelAlarm(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            val piArg = args.firstOrNull()
            if (piArg != null) {
                trackedAlarms[instanceId]?.remove(System.identityHashCode(piArg))
            }
            Timber.tag(TAG).d("Virtual alarm cancelled for instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetNextAlarm(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        return invokeOriginal(method, args)
    }

    /**
     * Cancel all alarms for a specific instance (called on app uninstall/stop).
     */
    fun cancelAllAlarmsForInstance(instanceId: String) {
        trackedAlarms.remove(instanceId)
        Timber.tag(TAG).d("All alarms cancelled for instance: $instanceId")
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Clipboard Manager Proxy — isolates clipboard per virtual app.
 *
 * Key methods:
 * - setPrimaryClip: Store in per-instance clipboard
 * - getPrimaryClip: Return from per-instance clipboard
 * - hasPrimaryClip: Check per-instance clipboard
 */
internal class ClipboardManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "ClipProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "setPrimaryClip" -> handleSetPrimaryClip(method, args, isVirtual)
                "getPrimaryClip" -> handleGetPrimaryClip(method, args, isVirtual)
                "hasPrimaryClip" -> handleHasPrimaryClip(method, args, isVirtual)
                "getPrimaryClipDescription" -> handleGetPrimaryClipDescription(method, args, isVirtual)
                "addPrimaryClipChangedListener" -> invokeOriginal(method, args)
                "removePrimaryClipChangedListener" -> invokeOriginal(method, args)
                "hasClipboardText" -> handleHasClipboardText(method, args, isVirtual)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleSetPrimaryClip(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            // Store clip data in isolated per-instance storage
            val clipData = args.firstOrNull()
            manager.setClipForInstance(instanceId, clipData)
            Timber.tag(TAG).d("Clipboard set for instance: $instanceId (isolated)")
            // Also set on real clipboard for cross-app paste support
            return invokeOriginal(method, args)
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetPrimaryClip(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            val clip = manager.getClipForInstance(instanceId)
            if (clip != null) {
                Timber.tag(TAG).d("Returning isolated clipboard for instance: $instanceId")
                return clip
            }
        }

        return invokeOriginal(method, args)
    }

    private fun handleHasPrimaryClip(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            return manager.getClipForInstance(instanceId) != null
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetPrimaryClipDescription(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            val clip = manager.getClipForInstance(instanceId)
            if (clip != null) {
                try {
                    val getDescMethod = clip::class.java.getDeclaredMethod("getDescription")
                    return getDescMethod.invoke(clip)
                } catch (_: Exception) { /* fall through */ }
            }
        }

        return invokeOriginal(method, args)
    }

    private fun handleHasClipboardText(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            val clip = manager.getClipForInstance(instanceId) ?: return false
            try {
                val getItemCount = clip::class.java.getDeclaredMethod("getItemCount")
                val count = getItemCount.invoke(clip) as Int
                return count > 0
            } catch (_: Exception) { /* fall through */ }
        }

        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Account Manager Proxy — filters/spoofs accounts for virtual apps.
 *
 * Key methods:
 * - getAccounts/getAccountsByType: Filter to virtual app's accounts only
 */
internal class AccountManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "AcctProxy"
    }

    // Per-instance account lists
    private val virtualAccounts = mutableMapOf<String, MutableList<Any>>()

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "getAccounts" -> handleGetAccounts(method, args, isVirtual)
                "getAccountsForPackage" -> handleGetAccounts(method, args, isVirtual)
                "getAccountsByType",
                "getAccountsByTypeForPackage" -> handleGetAccountsByType(method, args, isVirtual)
                "addAccountExplicitly" -> handleAddAccount(method, args, isVirtual)
                "removeAccount",
                "removeAccountAsUser" -> handleRemoveAccount(method, args, isVirtual)
                "getAuthToken",
                "getAuthTokenLabel" -> invokeOriginal(method, args)
                "hasFeatures" -> invokeOriginal(method, args)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleGetAccounts(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            val accounts = virtualAccounts[instanceId]
            if (accounts != null) {
                try {
                    val accountClass = Class.forName("android.accounts.Account")
                    val arr = java.lang.reflect.Array.newInstance(accountClass, accounts.size)
                    accounts.forEachIndexed { i, acct ->
                        java.lang.reflect.Array.set(arr, i, acct)
                    }
                    return arr
                } catch (_: Exception) { /* fall through */ }
            }
            // Return empty account array
            try {
                val accountClass = Class.forName("android.accounts.Account")
                return java.lang.reflect.Array.newInstance(accountClass, 0)
            } catch (_: Exception) { /* fall through */ }
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetAccountsByType(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val accountType = args?.firstOrNull() as? String
        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())

        if (accountType == "com.google" && instanceId != null) {
            // ---- ACCOUNT ISOLATION ----
            // Ask the GMS router for this instance's virtual account.
            // - Non-null result  → return ONLY this instance's account (full isolation)
            // - null result      → instance hasn't signed in yet, fall back to host accounts
            //                      so the user can complete the sign-in flow
            val router = manager.gmsRouter
            if (router != null) {
                val virtualAccounts = router.getVirtualGoogleAccounts(instanceId)
                if (virtualAccounts != null) {
                    // Instance is signed in — return isolated account only
                    Timber.tag(TAG).d("Account isolation: returning ${virtualAccounts.size} " +
                            "virtual account(s) for $instanceId (hiding host accounts)")
                    return virtualAccounts.toTypedArray()
                }
                // null = not yet signed in → allow host accounts for sign-in flow (fall through)
                Timber.tag(TAG).d("Account isolation: instance $instanceId not signed in — " +
                        "allowing host accounts for initial sign-in")
            }

            // Fallback: return real host Google accounts (for initial sign-in)
            try {
                val context = manager.getAppContext()
                if (context != null) {
                    val accountManager = android.accounts.AccountManager.get(context)
                    val hostGoogleAccounts = accountManager.getAccountsByType("com.google")
                    if (hostGoogleAccounts.isNotEmpty()) {
                        Timber.tag(TAG).d("Returning ${hostGoogleAccounts.size} host accounts for sign-in flow ($instanceId)")
                        return hostGoogleAccounts
                    }
                }
            } catch (e: Exception) {
                Timber.tag(TAG).w("Failed to get host Google accounts: ${e.message}")
            }
        }

        // For non-Google types or if host accounts unavailable, return virtual accounts
        return handleGetAccounts(method, args, true)
    }

    private fun handleAddAccount(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null && args.isNotEmpty()) {
            virtualAccounts.getOrPut(instanceId) { mutableListOf() }.add(args[0])
            Timber.tag(TAG).d("Added virtual account for instance: $instanceId")
            return true
        }

        return invokeOriginal(method, args)
    }

    private fun handleRemoveAccount(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null && args.isNotEmpty()) {
            virtualAccounts[instanceId]?.remove(args[0])
            Timber.tag(TAG).d("Removed virtual account for instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Window Manager Proxy — intercepts window management for overlay/toast control.
 */
internal class WindowManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "WinProxy"
    }

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "addView" -> handleAddView(method, args, isVirtual)
                "removeView" -> invokeOriginal(method, args)
                "updateViewLayout" -> invokeOriginal(method, args)
                "openSession" -> invokeOriginal(method, args)
                "getInitialDisplaySize" -> invokeOriginal(method, args)
                "hasNavigationBar" -> invokeOriginal(method, args)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleAddView(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)
        Timber.tag(TAG).d("Virtual app adding window view")
        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Audio Manager Proxy — intercepts audio focus and volume controls.
 */
internal class AudioManagerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "AudioProxy"
    }

    // Track audio focus per instance
    private val audioFocusHolders = mutableMapOf<String, Any?>()

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "requestAudioFocus" -> handleRequestAudioFocus(method, args, isVirtual)
                "abandonAudioFocus" -> handleAbandonAudioFocus(method, args, isVirtual)
                "adjustVolume",
                "adjustStreamVolume",
                "adjustSuggestedStreamVolume" -> handleAdjustVolume(method, args, isVirtual)
                "setStreamVolume" -> handleSetStreamVolume(method, args, isVirtual)
                "getStreamVolume",
                "getStreamMaxVolume" -> invokeOriginal(method, args)
                "setRingerMode",
                "getRingerMode" -> invokeOriginal(method, args)
                "isMusicActive" -> invokeOriginal(method, args)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            try { invokeOriginal(method, args) } catch (_: Exception) { null }
        }
    }

    private fun handleRequestAudioFocus(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null && args != null) {
            audioFocusHolders[instanceId] = args.firstOrNull()
            Timber.tag(TAG).d("Audio focus requested by instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun handleAbandonAudioFocus(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            audioFocusHolders.remove(instanceId)
            Timber.tag(TAG).d("Audio focus abandoned by instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun handleAdjustVolume(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        Timber.tag(TAG).d("Virtual app adjusting volume")
        return invokeOriginal(method, args)
    }

    private fun handleSetStreamVolume(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        Timber.tag(TAG).d("Virtual app setting stream volume")
        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
}

/**
 * Job Scheduler Proxy — isolates scheduled jobs per virtual app.
 *
 * Key methods:
 * - schedule: Tag with instanceId
 * - cancel/cancelAll: Route to instance-specific jobs
 * - getAllPendingJobs: Return only this instance's jobs
 */
internal class JobSchedulerProxyHandler(
    private val original: Any,
    private val manager: SystemServiceProxyManager
) : InvocationHandler {

    companion object {
        private const val TAG = "JobProxy"
    }

    // Track jobs per instance: instanceId -> set of jobIds
    private val trackedJobs = mutableMapOf<String, MutableSet<Int>>()
    // Original job component mappings: jobId -> original ComponentName
    private val jobComponentMappings = mutableMapOf<Int, android.content.ComponentName>()

    override fun invoke(proxy: Any, method: Method, args: Array<out Any>?): Any? {
        val callingPid = android.os.Process.myPid()
        val isVirtual = manager.isVirtualCallOrArgs(callingPid, args)

        return try {
            when (method.name) {
                "schedule" -> handleSchedule(method, args, isVirtual)
                "enqueue" -> handleSchedule(method, args, isVirtual)
                "cancel" -> handleCancel(method, args, isVirtual)
                "cancelAll" -> handleCancelAll(method, args, isVirtual)
                "getAllPendingJobs" -> handleGetAllPendingJobs(method, args, isVirtual)
                "getPendingJob" -> handleGetPendingJob(method, args, isVirtual)
                else -> invokeOriginal(method, args)
            }
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Error in ${method.name}")
            // For schedule/enqueue, don't retry invokeOriginal — it will fail again
            // and produce UndeclaredThrowableException. Return success silently.
            if (method.name == "schedule" || method.name == "enqueue") {
                1 // JobScheduler.RESULT_SUCCESS
            } else {
                try { invokeOriginal(method, args) } catch (_: Exception) { null }
            }
        }
    }

    private fun handleSchedule(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return try {
            invokeOriginal(method, args)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val cause = e.cause ?: e.targetException
            if (cause is SecurityException ||
                    (cause is IllegalArgumentException && cause.message?.contains("cannot schedule job") == true)) {
                Timber.tag(TAG).w("JobScheduler schedule suppressed (non-virtual): ${cause.message}")
                1 // JobScheduler.RESULT_SUCCESS
            } else {
                throw e
            }
        }

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null && args.isNotEmpty()) {
            try {
                val jobInfo = args[0]
                val getIdMethod = jobInfo::class.java.getDeclaredMethod("getId")
                val jobId = getIdMethod.invoke(jobInfo) as Int
                trackedJobs.getOrPut(instanceId) { mutableSetOf() }.add(jobId)

                // Rewrite the component name to our stub service so the system
                // doesn't reject the job (guest components aren't registered)
                try {
                    // JobInfo stores the component in 'service' (older API) or 'mService'
                    val serviceField = findField(jobInfo::class.java, "service")
                        ?: findField(jobInfo::class.java, "mService")
                        ?: jobInfo::class.java.getDeclaredField("service")
                    serviceField.isAccessible = true
                    val originalComponent = serviceField.get(jobInfo) as? android.content.ComponentName
                    if (originalComponent != null && manager.isVirtualPackage(originalComponent.packageName)) {
                        // Map to a NEXTVM stub service in the appropriate process slot
                        val processSlot = manager.getSlotForInstance(instanceId) ?: 0
                        val stubServiceName = "com.nextvm.app.stub.StubService\$P${processSlot}\$S00"
                        val hostPackage = manager.getAppContext()?.packageName ?: "com.nextvm.app"
                        val stubComponent = android.content.ComponentName(hostPackage, stubServiceName)
                        serviceField.set(jobInfo, stubComponent)

                        // Store the original component mapping for dispatch
                        jobComponentMappings[jobId] = originalComponent
                        Timber.tag(TAG).d("Job $jobId rewritten: ${originalComponent.shortClassName} -> ${stubComponent.shortClassName}")
                    }
                } catch (e: Exception) {
                    Timber.tag(TAG).w("Failed to rewrite job component: ${e.message}")
                }

                Timber.tag(TAG).d("Job $jobId scheduled for instance: $instanceId")
            } catch (_: Exception) { /* OK */ }
        }

        // Wrap invokeOriginal to catch UID mismatch errors from the system.
        // Virtual apps run under NEXTVM's UID, but JobScheduler checks that
        // the UID matches the package in the JobInfo. If rewrite failed or
        // the system still rejects it, return RESULT_SUCCESS (1) silently.
        return try {
            invokeOriginal(method, args)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val cause = e.cause ?: e.targetException
            if (cause is SecurityException ||
                    (cause is IllegalArgumentException && cause.message?.contains("cannot schedule job") == true)) {
                Timber.tag(TAG).w("JobScheduler schedule suppressed for virtual app: ${cause?.message}")
                1 // JobScheduler.RESULT_SUCCESS
            } else {
                throw e
            }
        }
    }

    private fun handleCancel(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual || args == null) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null && args.isNotEmpty()) {
            val jobId = args[0] as? Int
            if (jobId != null) {
                trackedJobs[instanceId]?.remove(jobId)
                Timber.tag(TAG).d("Job $jobId cancelled for instance: $instanceId")
            }
        }

        return invokeOriginal(method, args)
    }

    private fun handleCancelAll(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        if (instanceId != null) {
            trackedJobs.remove(instanceId)
            Timber.tag(TAG).d("All jobs cancelled for instance: $instanceId")
        }

        return invokeOriginal(method, args)
    }

    private fun handleGetAllPendingJobs(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)

        // Get all jobs from real scheduler and filter to this instance's tracked ones
        val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
        val allJobs = invokeOriginal(method, args) as? List<*> ?: return emptyList<Any>()

        if (instanceId != null) {
            val trackedIds = trackedJobs[instanceId] ?: return emptyList<Any>()
            return allJobs.filter { job ->
                try {
                    val getIdMethod = job!!::class.java.getDeclaredMethod("getId")
                    val jobId = getIdMethod.invoke(job) as Int
                    trackedIds.contains(jobId)
                } catch (_: Exception) {
                    false
                }
            }
        }

        return allJobs
    }

    private fun handleGetPendingJob(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
        if (!isVirtual) return invokeOriginal(method, args)
        return invokeOriginal(method, args)
    }

    private fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
        return if (args != null) method.invoke(original, *args) else method.invoke(original)
    }
    }

    // ==================== Priority 3 Proxy Install Methods ====================

    /**
     * Sensor service proxy — isolate sensor access per virtual app.
     * NOTE: SensorService is a native (C++) AIDL service — there is no Java-side
     * ISensorServer interface to proxy. Sensor interception must be done via
     * SensorManager Java API hooks or native PLT hooks if needed.
     * For now, skip — sensors pass through unmodified.
     */
    private fun installSensorProxy(context: Context) {
        Timber.tag(TAG).d("Sensor proxy skipped (native AIDL, no Java interface)")
    }

    /**
     * Camera service proxy — control camera access per virtual app.
     * Intercepts: connect, getCameraInfo, getNumberOfCameras
     */
    private fun installCameraProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_CAMERA,
            "android.hardware.ICameraService"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    val methodName = method.name
                    when (methodName) {
                        "connectDevice", "connect" -> {
                            val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
                            Timber.tag(TAG).d("Camera connect from virtual app: $instanceId")
                            // Allow camera access — permission is checked by VirtualPermissionManager
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * WiFi service proxy — isolate WiFi state and scan results per virtual app.
     * Intercepts: getScanResults, getConnectionInfo, getConfiguredNetworks
     */
    private fun installWifiProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_WIFI,
            "android.net.wifi.IWifiManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    // SvcTrace (v31, W1 narrow): record-only tracing at
                    // this handler's single entry point; dispatch below
                    // is the pre-v31 logic, unchanged.
                    svcTrace("wifi", method.name, true, null, args, null, -1, null)
                    val result = try {
                        when (method.name) {
                            "getConnectionInfo" -> {
                                // Spoof MAC address if device profile has one
                                val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
                                val profile = if (instanceId != null) manager.getDeviceProfile(instanceId) else null
                                val connInfo = invokeOriginal(method, args)
                                if (profile != null && connInfo != null) {
                                    try {
                                        val macField = com.nextvm.core.common.findField(connInfo::class.java, "mMacAddress")
                                        macField?.isAccessible = true
                                        macField?.set(connInfo, profile.macAddress)
                                    } catch (_: Exception) { /* best effort */ }
                                }
                                connInfo
                            }
                            else -> invokeOriginal(method, args)
                        }
                    } catch (e: Exception) {
                        svcTrace("wifi", method.name, true, null, args, null, 0, e)
                        throw e
                    }
                    svcTrace("wifi", method.name, true, null, args, result, 0, null)
                    return result
                }
            }
        }
    }

    /**
     * Bluetooth service proxy — isolate Bluetooth access per virtual app.
     * Intercepts: getAddress, getName, enable, disable
     */
    private fun installBluetoothProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_BLUETOOTH,
            "android.bluetooth.IBluetoothManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    when (method.name) {
                        "getAddress" -> {
                            // Spoof Bluetooth address for privacy
                            val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
                            if (instanceId != null) {
                                return "02:00:00:00:00:00" // Standard spoofed address
                            }
                        }
                        "enable", "disable" -> {
                            // Block enable/disable requests from virtual apps
                            Timber.tag(TAG).d("Blocked Bluetooth ${method.name} from virtual app")
                            return false
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Download service proxy — DownloadManager uses ContentProvider (not ServiceManager).
     * We proxy the DownloadManager's internal ContentResolver-based operations
     * by marking it as installed and intercepting via the manager instance.
     */
    private fun installDownloadProxy(context: Context) {
        try {
            val dm = context.getSystemService(Context.DOWNLOAD_SERVICE)
            if (dm != null) {
                // DownloadManager works via ContentResolver — proxy its package name
                // so downloads are attributed to the host app
                val pkgField = findField(dm::class.java, "mPackageName")
                if (pkgField != null) {
                    pkgField.isAccessible = true
                    originalServices[SERVICE_DOWNLOAD] = dm
                    installedProxies.add(SERVICE_DOWNLOAD)
                    Timber.tag(TAG).i("DownloadManager proxy installed (package rewrite)")
                } else {
                    Timber.tag(TAG).d("DownloadManager.mPackageName field not found — skipping")
                }
            } else {
                Timber.tag(TAG).d("DownloadManager not available — skipping")
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w("DownloadManager proxy failed: ${e.message}")
        }
    }

    /**
     * Input method proxy — manage soft keyboard per virtual app.
     * Intercepts: showSoftInput, hideSoftInput, getInputMethodList
     */
    private fun installInputMethodProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_INPUT_METHOD,
            "com.android.internal.view.IInputMethodManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    // Pass through — keyboard sharing between host and guest is expected
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    // Per-instance virtual sdcard root paths: instanceId -> absolute path
    private val virtualSdcardRoots = mutableMapOf<String, String>()

    /**
     * Register the virtual external storage (sdcard) root for an instance.
     * Must be called during app install / before launch so the storage proxy
     * can return correct volume information.
     */
    fun registerVirtualSdcard(instanceId: String, sdcardRoot: String) {
        virtualSdcardRoots[instanceId] = sdcardRoot
    }

    /**
     * Storage/mount service proxy — redirect storage queries per virtual app.
     * Intercepts: getVolumeList, getStorageVolume, getExternalStorageState,
     *             getVolumeInfo, getPrimaryStorageUuid
     *
     * File explorer apps call StorageManager.getStorageVolumes() to discover
     * available storage. Without this proxy they see the host's real volumes.
     * We intercept and return a single virtual primary volume pointing at
     * the per-instance sandboxed sdcard directory.
     */
    private fun installStorageProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_STORAGE,
            "android.os.storage.IStorageManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
                    val sdcardRoot = if (instanceId != null) manager.virtualSdcardRoots[instanceId] else null

                    when (method.name) {
                        // getVolumeList — returns StorageVolume[] to the caller.
                        // Apps (especially file explorers) iterate this list to find
                        // browsable storage roots.
                        "getVolumeList" -> {
                            if (sdcardRoot == null) return invokeOriginal(method, args)
                            return try {
                                buildVirtualVolumeList(sdcardRoot)
                            } catch (e: Exception) {
                                Timber.tag(TAG).w("getVolumeList hook failed: ${e.message}")
                                invokeOriginal(method, args)
                            }
                        }

                        // getExternalStorageState — file explorers check this before browsing
                        "getExternalStorageState" -> {
                            return Environment.MEDIA_MOUNTED
                        }

                        // isExternalStorageEmulated — most virtual storage is "emulated"
                        "isExternalStorageEmulated" -> {
                            return true
                        }

                        // isExternalStorageRemovable — our virtual sdcard is not removable
                        "isExternalStorageRemovable" -> {
                            return false
                        }

                        // getPrimaryStorageUuid — return a deterministic fake UUID
                        "getPrimaryStorageUuid" -> {
                            return "primary"
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Build a StorageVolume[] containing a single virtual primary volume.
     *
     * StorageVolume is a parcelable with these key fields:
     *   mId, mPath/mInternalPath, mDescription, mPrimary, mRemovable,
     *   mEmulated, mState, mFsUuid, mOwner
     *
     * We get a real StorageVolume from the system and patch its path fields
     * to point to our virtual sdcard directory.
     */
    private fun buildVirtualVolumeList(sdcardRoot: String): Any? {
        val svClass = Class.forName("android.os.storage.StorageVolume")
        val virtualDir = java.io.File(sdcardRoot)

        // Get the real primary volume as a template
        val storageManager = appContext?.getSystemService(Context.STORAGE_SERVICE)
            as? android.os.storage.StorageManager
        val realVolumes = storageManager?.storageVolumes

        if (realVolumes.isNullOrEmpty()) return null

        val primary = realVolumes.first { it.isPrimary }

        // Clone the primary volume and patch its internal path to our virtual sdcard
        val pathField = findField(svClass, "mPath")
            ?: findField(svClass, "mInternalPath")
        val internalPathField = findField(svClass, "mInternalPath")

        if (pathField != null) {
            pathField.isAccessible = true
            pathField.set(primary, virtualDir)
        }
        if (internalPathField != null && internalPathField != pathField) {
            internalPathField.isAccessible = true
            internalPathField.set(primary, virtualDir)
        }

        // Return as raw array (IStorageManager returns StorageVolume[])
        val array = java.lang.reflect.Array.newInstance(svClass, 1)
        java.lang.reflect.Array.set(array, 0, primary)
        return array
    }

    /**
     * Display service proxy — spoof display metrics per virtual app.
     * Intercepts: getDisplayInfo, getRealDisplayInfo
     */
    private fun installDisplayProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_DISPLAY,
            "android.hardware.display.IDisplayManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    when (method.name) {
                        "getDisplayInfo" -> {
                            val result = invokeOriginal(method, args)
                            val instanceId = manager.getInstanceForPid(android.os.Process.myPid())
                            val profile = if (instanceId != null) manager.getDeviceProfile(instanceId) else null
                            if (profile != null && result != null) {
                                // Spoof display dimensions from device profile
                                try {
                                    val wField = com.nextvm.core.common.findField(result::class.java, "logicalWidth")
                                    val hField = com.nextvm.core.common.findField(result::class.java, "logicalHeight")
                                    val dField = com.nextvm.core.common.findField(result::class.java, "logicalDensityDpi")
                                    if (profile.screenWidthDp > 0) {
                                        wField?.isAccessible = true
                                        wField?.set(result, profile.screenWidthDp)
                                    }
                                    if (profile.screenHeightDp > 0) {
                                        hField?.isAccessible = true
                                        hField?.set(result, profile.screenHeightDp)
                                    }
                                    if (profile.densityDpi > 0) {
                                        dField?.isAccessible = true
                                        dField?.set(result, profile.densityDpi)
                                    }
                                } catch (_: Exception) { /* best effort */ }
                            }
                            return result
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Power service proxy — manage wake locks per virtual app.
     * Intercepts: acquireWakeLock, releaseWakeLock
     */
    private fun installPowerProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_POWER,
            "android.os.IPowerManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                private val virtualWakeLocks = mutableMapOf<String, MutableSet<Any>>()

                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    val instanceId = manager.getInstanceForPid(android.os.Process.myPid())

                    when (method.name) {
                        "acquireWakeLock" -> {
                            if (instanceId != null && args != null && args.size >= 2) {
                                val lock = args[0]
                                virtualWakeLocks.getOrPut(instanceId) { mutableSetOf() }.add(lock)
                                Timber.tag(TAG).d("Wake lock acquired by virtual app: $instanceId")
                            }
                        }
                        "releaseWakeLock" -> {
                            if (instanceId != null && args != null && args.isNotEmpty()) {
                                val lock = args[0]
                                virtualWakeLocks[instanceId]?.remove(lock)
                            }
                        }
                        "isInteractive", "isScreenOn" -> {
                            // Always report screen as on for virtual apps
                            return true
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Vibrator service proxy — limit vibration from virtual apps.
     * On API 31+ uses IVibratorManagerService, older uses IVibratorService.
     * Intercepts: vibrate, cancel
     */
    private fun installVibratorProxy(context: Context) {
        val interfaceName = if (android.os.Build.VERSION.SDK_INT >= 31) {
            "android.os.IVibratorManagerService"
        } else {
            "android.os.IVibratorService"
        }
        installViaServiceManagerCache(
            SERVICE_VIBRATOR,
            interfaceName
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    when (method.name) {
                        "vibrate" -> {
                            // Allow vibration — it's expected behavior
                            Timber.tag(TAG).d("Vibrate from virtual app")
                        }
                        "hasVibrator" -> return true
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Usage stats proxy — isolate app usage data per virtual app.
     * Intercepts: queryUsageStats, queryEvents
     */
    private fun installUsageStatsProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_USAGE_STATS,
            "android.app.usage.IUsageStatsManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    when (method.name) {
                        "queryUsageStats", "queryEvents", "queryConfigurationStats" -> {
                            // Return empty results — virtual apps shouldn't see real usage data
                            return emptyList<Any>()
                        }
                        "isAppInactive" -> return false
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Keyguard/StatusBar proxy — manage lock screen interaction per virtual app.
     * Intercepts: isKeyguardLocked, isKeyguardSecure, dismissKeyguard
     */
    private fun installKeyguardProxy(context: Context) {
        installViaServiceManagerCache(
            "statusbar",
            "com.android.internal.statusbar.IStatusBarService"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)

                    when (method.name) {
                        "isKeyguardLocked" -> return false  // Appear unlocked to guest apps
                        "isKeyguardSecure" -> return false   // No secure keyguard
                        "dismissKeyguard" -> {
                            Timber.tag(TAG).d("Keyguard dismiss from virtual app (no-op)")
                            return null
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * AppOps proxy — Auto-allow ALL AppOps operations for virtual apps.
     *
     * This is CRITICAL for permission auto-granting because many "special" permissions
     * (MANAGE_EXTERNAL_STORAGE, SYSTEM_ALERT_WINDOW, WRITE_SETTINGS, etc.) are backed
     * by AppOps rather than standard runtime permissions. When a guest app calls:
     *   - Environment.isExternalStorageManager() → checkOp(OP_MANAGE_EXTERNAL_STORAGE)
     *   - Settings.canDrawOverlays() → checkOp(OP_SYSTEM_ALERT_WINDOW)
     *   - Settings.System.canWrite() → checkOp(OP_WRITE_SETTINGS)
     *
     * These all go through IAppOpsService.checkOperation(). By returning MODE_ALLOWED (0)
     * for ALL operations, we ensure all permission checks pass inside the VM.
     */
    /**
     * UserManager proxy — intercepts IUserManager calls that require MANAGE_USERS.
     *
     * Play Store and GMS call UserManager.getUserCount(), getUsers(), getProfiles()
     * which throw SecurityException: "You either need MANAGE_USERS or CREATE_USERS
     * permission to: query users". We return safe defaults to prevent crashes.
     */
    private fun installUserManagerProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_USER,
            "android.os.IUserManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    return when (method.name) {
                        // getUserCount() → int — return 1 (single user)
                        "getUserCount" -> 1

                        // getUsers(boolean, boolean, boolean) → List<UserInfo>
                        // Return empty list to avoid SecurityException
                        "getUsers" -> {
                            try {
                                invokeOriginal(method, args)
                            } catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException) {
                                    Timber.tag(TAG).d("UserManager.getUsers() SecurityException swallowed — returning empty list")
                                    emptyList<Any>()
                                } else {
                                    throw e
                                }
                            }
                        }

                        // getProfiles(int userId, boolean enabledOnly) → List<UserInfo>
                        "getProfiles" -> {
                            try {
                                invokeOriginal(method, args)
                            } catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException) {
                                    Timber.tag(TAG).d("UserManager.getProfiles() SecurityException swallowed — returning empty list")
                                    emptyList<Any>()
                                } else {
                                    throw e
                                }
                            }
                        }

                        // getUserInfo(int userId) → UserInfo
                        "getUserInfo" -> {
                            try {
                                invokeOriginal(method, args)
                            } catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException) {
                                    Timber.tag(TAG).d("UserManager.getUserInfo() SecurityException swallowed — returning null")
                                    null
                                } else {
                                    throw e
                                }
                            }
                        }

                        // isUserUnlocked / isUserRunning → true
                        "isUserUnlocked", "isUserRunning", "isUserUnlockingOrUnlocked" -> true

                        // getProfileParent → null (no work profile)
                        "getProfileParent" -> null

                        // getUserSerialNumber → 0
                        "getUserSerialNumber" -> 0

                        // getUserHandle → 0
                        "getUserHandle" -> 0

                        // isSameProfileGroup → false
                        "isSameProfileGroup" -> false

                        // isQuietModeEnabled → false
                        "isQuietModeEnabled" -> false

                        // Default: pass through, catch SecurityException
                        else -> {
                            try {
                                invokeOriginal(method, args)
                            } catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException &&
                                    (cause.message?.contains("MANAGE_USERS") == true ||
                                     cause.message?.contains("CREATE_USERS") == true ||
                                     cause.message?.contains("query users") == true)
                                ) {
                                    Timber.tag(TAG).d("UserManager.${method.name}() SecurityException swallowed")
                                    // Return appropriate default based on return type
                                    when (method.returnType) {
                                        Boolean::class.javaPrimitiveType -> false
                                        Int::class.javaPrimitiveType -> 0
                                        Long::class.javaPrimitiveType -> 0L
                                        java.util.List::class.java -> emptyList<Any>()
                                        else -> null
                                    }
                                } else {
                                    throw e
                                }
                            }
                        }
                    }
                }
            }
        }
        if (SERVICE_USER in installedProxies) {
            Timber.tag(TAG).d("UserManager proxy installed")
        }
    }

    private fun installAppOpsProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_APP_OPS,
            "com.android.internal.app.IAppOpsService"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    when (method.name) {
                        // checkOperation(int code, int uid, String packageName) → int mode
                        "checkOperation",
                        "checkOperationRaw",
                        "checkOp",
                        "checkOpNoThrow",
                        "checkOpRaw" -> {
                            // Return MODE_ALLOWED (0) for ALL operations in the VM
                            Timber.tag(TAG).d("AppOps.${method.name} → MODE_ALLOWED (auto-grant)")
                            return 0 // AppOpsManager.MODE_ALLOWED
                        }

                        // noteOperation / noteOp — record an op and return mode
                        "noteOperation",
                        "noteOp",
                        "noteOpNoThrow" -> {
                            Timber.tag(TAG).d("AppOps.${method.name} → MODE_ALLOWED (auto-grant)")
                            return 0 // AppOpsManager.MODE_ALLOWED
                        }

                        // startOperation / startOp — long-running ops
                        "startOperation",
                        "startOp",
                        "startOpNoThrow" -> {
                            Timber.tag(TAG).d("AppOps.${method.name} → MODE_ALLOWED (auto-grant)")
                            return 0 // AppOpsManager.MODE_ALLOWED
                        }

                        // checkPackage — verify package owns UID (always pass for virtual apps)
                        "checkPackage" -> {
                            return null // No-op, no exception = success
                        }

                        // noteProxyOperation — proxy ops from guest context
                        "noteProxyOperation",
                        "noteProxyOpNoThrow" -> {
                            return 0 // MODE_ALLOWED
                        }

                        // unsafeCheckOp — new API 30+ check
                        "unsafeCheckOp",
                        "unsafeCheckOpNoThrow",
                        "unsafeCheckOpRaw",
                        "unsafeCheckOpRawNoThrow" -> {
                            return 0 // MODE_ALLOWED
                        }

                        // setMode — guest app trying to change its own AppOps (no-op in VM)
                        "setMode" -> {
                            Timber.tag(TAG).d("AppOps.setMode no-op in VM")
                            return null
                        }

                        // getPackagesForOps — return empty list
                        "getPackagesForOps" -> {
                            return try { invokeOriginal(method, args) } catch (_: Exception) { null }
                        }
                    }

                    // All other AppOps methods — pass through
                    return try {
                        invokeOriginal(method, args)
                    } catch (e: Exception) {
                        val cause = e.cause ?: e
                        if (cause is SecurityException) {
                            Timber.tag(TAG).w("AppOps SecurityException swallowed for ${method.name}: ${cause.message}")
                            null
                        } else {
                            // For unknown methods, return null rather than crashing
                            Timber.tag(TAG).w("AppOps.${method.name} failed: ${e.message}")
                            null
                        }
                    }
                }
            }
        }
    }

    // ====================================================================
    // Priority 4 — Additional service proxies for full coverage
    // ====================================================================

    /**
     * Device policy proxy — prevent guest apps from calling device admin APIs.
     */
    private fun installDevicePolicyProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_DEVICE_POLICY,
            "android.app.admin.IDevicePolicyManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)
                    // Block device policy modifications from virtual apps
                    return when (method.name) {
                        "isDeviceOwnerApp", "isProfileOwnerApp" -> false
                        "getActiveAdmins" -> emptyList<Any>()
                        "hasGrantedPolicy" -> false
                        else -> {
                            try { invokeOriginal(method, args) }
                            catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException) null
                                else throw e
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Accessibility service proxy — pass through with package name rewrite.
     */
    private fun installAccessibilityProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_ACCESSIBILITY,
            "android.view.accessibility.IAccessibilityManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    // Rewrite package names in args, pass through
                    if (isVirtual && args != null) {
                        val newArgs = args.toMutableList().toTypedArray()
                        for (i in newArgs.indices) {
                            if (newArgs[i] is String && manager.isVirtualPackage(newArgs[i] as String)) {
                                newArgs[i] = VirtualConstants.HOST_PACKAGE
                            }
                        }
                        return try { method.invoke(original, *newArgs) }
                        catch (e: Exception) {
                            val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                            if (cause is SecurityException) null else throw e
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Media session proxy — manage audio focus per virtual app.
     */
    private fun installMediaSessionProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_MEDIA_SESSION,
            "android.media.session.ISessionManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)
                    // Rewrite package names for session creation
                    if (args != null) {
                        val newArgs = args.toMutableList().toTypedArray()
                        for (i in newArgs.indices) {
                            if (newArgs[i] is String && manager.isVirtualPackage(newArgs[i] as String)) {
                                newArgs[i] = VirtualConstants.HOST_PACKAGE
                            }
                        }
                        return try { method.invoke(original, *newArgs) }
                        catch (e: Exception) {
                            val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                            if (cause is SecurityException) null else throw e
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Network stats proxy — return empty stats for virtual apps.
     */
    private fun installNetworkStatsProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_NETWORK_STATS,
            "android.net.INetworkStatsService"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)
                    return try { invokeOriginal(method, args) }
                    catch (e: Exception) {
                        val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                        if (cause is SecurityException) {
                            when (method.returnType) {
                                Boolean::class.javaPrimitiveType -> false
                                Long::class.javaPrimitiveType -> 0L
                                Int::class.javaPrimitiveType -> 0
                                else -> null
                            }
                        } else throw e
                    }
                }
            }
        }
    }

    /**
     * Shortcut service proxy — rewrite package names for launcher shortcuts.
     */
    private fun installShortcutProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_SHORTCUT,
            "android.content.pm.IShortcutService"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    // v112: NO gate for set/add/update. launch137 proved
                    // both gates are always false in a guest process:
                    // pidToInstance is never filled (registerProcessPid
                    // has no callers) and virtualPackages is never
                    // filled either (SystemServiceProxyManager.
                    // registerVirtualApp has no callers; VirtualEngine
                    // registers with BinderProxyManager instead). Any
                    // gate built on those two maps can never pass, so
                    // the sanitizer below never ran in launches
                    // 131/132/133/136/137. This proxy is installed by
                    // VirtualEngine in guest processes, and dropping an
                    // unparcelable Bitmap shortcut is safe for a host
                    // caller too, so unconditional cleaning is the
                    // correct scope here. Other shortcut-service
                    // methods are forwarded unchanged.
                    if (method.name !in setOf(
                            "setDynamicShortcuts",
                            "addDynamicShortcuts",
                            "updateShortcuts"
                        )
                    ) {
                        return invokeOriginal(method, args)
                    }
                    // Probe first, via direct Log (v112 reroute), so
                    // the next run's log proves the call reached the
                    // proxy and what the gate values were, even though
                    // they no longer decide anything.
                    val orArgs = manager.isVirtualCallOrArgs(
                        android.os.Process.myPid(), args)
                    ShortcutProbe.log(method.name, args, isVirtual, orArgs)
                    if (args != null) {
                        val newArgs = args.toMutableList().toTypedArray()
                        for (i in newArgs.indices) {
                            if (newArgs[i] is String && manager.isVirtualPackage(newArgs[i] as String)) {
                                newArgs[i] = VirtualConstants.HOST_PACKAGE
                            }
                        }
                        for (i in newArgs.indices) {
                            val arg = newArgs[i] ?: continue
                            if (arg is List<*> && arg.isNotEmpty()
                                && arg[0] is android.content.pm.ShortcutInfo
                            ) {
                                @Suppress("UNCHECKED_CAST")
                                val kept = ShortcutInfoSanitizer.sanitize(
                                    arg as List<android.content.pm.ShortcutInfo>
                                )
                                if (kept.isEmpty()) return null
                                newArgs[i] = kept
                            } else if (arg.javaClass.name ==
                                "android.content.pm.ParceledListSlice"
                            ) {
                                val keptSlice =
                                    ShortcutInfoSanitizer.sanitizeSlice(arg)
                                        ?: return null
                                newArgs[i] = keptSlice
                            }
                        }
                        return try { method.invoke(original, *newArgs) }
                        catch (e: Exception) {
                            val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                            if (cause is SecurityException) null else throw e
                        }
                    }
                    return invokeOriginal(method, args)
                }
            }
        }
    }

    /**
     * Wallpaper service proxy — allow guest apps to get wallpaper info.
     */
    private fun installWallpaperProxy(context: Context) {
        installViaServiceManagerCache(
            SERVICE_WALLPAPER,
            "android.app.IWallpaperManager"
        ) { original ->
            object : BaseServiceProxy(original, this) {
                override fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any? {
                    if (!isVirtual) return invokeOriginal(method, args)
                    return when (method.name) {
                        "setWallpaper", "setWallpaperComponent" -> {
                            Timber.tag(TAG).d("Blocked wallpaper change from virtual app")
                            null
                        }
                        else -> {
                            try { invokeOriginal(method, args) }
                            catch (e: Exception) {
                                val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                                if (cause is SecurityException) null else throw e
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Abstract base for service proxies — provides common invoke + isVirtual check.
     */
    abstract class BaseServiceProxy(
        protected val original: Any,
        protected val manager: SystemServiceProxyManager
    ) : java.lang.reflect.InvocationHandler {

        override fun invoke(proxy: Any?, method: Method, args: Array<out Any>?): Any? {
            if (method.declaringClass == Object::class.java) {
                return if (args != null) method.invoke(original, *args)
                else method.invoke(original)
            }

            // Handle IInterface.asBinder() — return the original's binder
            if (method.name == "asBinder" && method.parameterCount == 0) {
                return method.invoke(original)
            }

            val isVirtual = manager.isVirtualApp(android.os.Process.myPid())
            return handleMethod(method, args, isVirtual)
        }

        abstract fun handleMethod(method: Method, args: Array<out Any>?, isVirtual: Boolean): Any?

        protected fun invokeOriginal(method: Method, args: Array<out Any>?): Any? {
            return if (args != null) method.invoke(original, *args)
            else method.invoke(original)
        }
    }

    /**
     * IBinder wrapper for ServiceManager.sCache replacement.
     *
     * When framework code calls ServiceManager.getService(name), it gets this wrapper.
     * When Stub.asInterface(binder) is called, it invokes queryLocalInterface(DESCRIPTOR)
     * which returns our proxied interface — thus intercepting all subsequent calls.
     *
     * Only queryLocalInterface() matters — Binder base class handles the rest.
     * Since our proxy interface is returned directly, transact() is never called.
     */
    private class ServiceBinderWrapper(
        private val originalBinder: android.os.IBinder,
        private val proxyInterface: Any,
        private val descriptor: String
    ) : android.os.Binder() {

        override fun queryLocalInterface(desc: String): android.os.IInterface? {
            if (desc == descriptor) {
                return proxyInterface as? android.os.IInterface
            }
            return null
        }

        override fun getInterfaceDescriptor(): String = descriptor
    }
}

// ==================== SvcTrace (v31) ====================
// Record-only tracing for the highest-suspicion service handlers
// (connectivity / telephony / wifi). Exists to find the synchronous
// system-service query whose sandbox answer stalls a guest's init
// pipeline (splash hang): e.g. connectivity returning null because the
// instance's NetworkPolicy was judged OFFLINE. Never alters results.
// NOTE: this must stay at file top level — the handler classes above
// are nested inside SystemServiceProxyManager despite their column-0
// declarations, so a helper placed between them lands in the class
// body where a top-level const/fun is illegal (v31 first build broke
// exactly here).
private const val SVC_TRACE_MAX = 400
private val svcTraceCount = java.util.concurrent.atomic.AtomicInteger(0)

internal fun svcTrace(
    service: String,
    methodName: String,
    isVirtual: Boolean,
    policy: String?,
    args: Array<out Any>?,
    result: Any?,
    phase: Int,
    error: Throwable?
) {
    try {
        val n = svcTraceCount.incrementAndGet()
        if (n > SVC_TRACE_MAX) return
        val sb = StringBuilder()
        sb.append(if (phase < 0) ">> " else "<< ")
            .append(service).append('.').append(methodName)
            .append(" virt=").append(isVirtual)
        if (policy != null) sb.append(" policy=").append(policy)
        if (phase < 0 && args != null) {
            for (a in args) {
                when (a) {
                    is String -> sb.append(" str=").append(a)
                    is Int -> sb.append(" int=").append(a)
                    is android.content.ComponentName -> sb.append(" cmp=")
                        .append(a.flattenToShortString())
                    else -> { /* binder/callback objects: skip */ }
                }
            }
        }
        if (phase >= 0) {
            sb.append(" -> ")
            if (error != null) {
                sb.append('!').append(error.javaClass.simpleName)
                    .append(": ").append(error.message)
            } else {
                sb.append(
                    when (result) {
                        null -> "null"
                        is Int -> "int=$result"
                        is Long -> "long=$result"
                        is Boolean -> "bool=$result"
                        is String -> "str(len=${result.length})"
                        is List<*> -> "List[${result.size}]"
                        is Array<*> -> "Array[${result.size}]"
                        else -> result.javaClass.simpleName
                    }
                )
            }
        }
        Timber.tag("SvcTrace").i(sb.toString())
    } catch (_: Exception) {
        // Tracing must never break the proxied call.
    }
}
