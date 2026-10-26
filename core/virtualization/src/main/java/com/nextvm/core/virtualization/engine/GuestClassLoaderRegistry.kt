package com.nextvm.core.virtualization.engine

import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap

/**
 * GuestClassLoaderRegistry — Global, process-wide registry of guest app ClassLoaders.
 *
 * ClassLoaders are registered at TWO points:
 *   1. At install time (VirtualEngine.installApp) — guarantees availability
 *   2. At launch time (VirtualEngine.getOrCreateClassLoader) — lazy fallback
 *
 * This registry is accessed by:
 *   - NextVmInstrumentation.newActivity() — to load guest Activity classes
 *   - VirtualClassLoaderInjector — to inject into LoadedApk.mClassLoader
 *   - VirtualResourceManager — for resource ClassLoader binding
 *
 * Thread-safe: uses ConcurrentHashMap for concurrent access from multiple processes.
 */
object GuestClassLoaderRegistry {

    private const val TAG = "GuestCLRegistry"

    /** Package name → ClassLoader mapping (strongest reference, prevents GC) */
    private val byPackageName = ConcurrentHashMap<String, ClassLoader>()

    /** Instance ID → ClassLoader mapping */
    private val byInstanceId = ConcurrentHashMap<String, ClassLoader>()

    /**
     * Register a ClassLoader for a guest app.
     * Called during APK install and at launch time.
     */
    fun register(packageName: String, instanceId: String, classLoader: ClassLoader) {
        byPackageName[packageName] = classLoader
        byInstanceId[instanceId] = classLoader
        Timber.tag(TAG).d("Registered ClassLoader for $packageName ($instanceId)")
    }

    /**
     * Get ClassLoader by package name.
     */
    fun getByPackage(packageName: String): ClassLoader? = byPackageName[packageName]

    /**
     * Get ClassLoader by instance ID.
     */
    fun getByInstanceId(instanceId: String): ClassLoader? = byInstanceId[instanceId]

    /** Find the guest instance that owns an exact ClassLoader object. */
    fun findInstanceIdByClassLoader(classLoader: ClassLoader?): String? {
        if (classLoader == null) return null
        return byInstanceId.entries.firstOrNull { it.value === classLoader }?.key
    }

    /**
     * Get all registered ClassLoaders (for exhaustive retry in newActivity).
     */
    fun getAllLoaders(): Collection<ClassLoader> = byPackageName.values

    /**
     * FIX 1: Brute-force scan — find a registered ClassLoader that can load the given class.
     * Used as last-resort strategy when package/instanceId lookups fail.
     */
    fun findLoaderForClass(className: String): ClassLoader? {
        for ((key, loader) in byPackageName) {
            try {
                loader.loadClass(className)
                Timber.tag(TAG).d("findLoaderForClass: found $className via loader for $key")
                return loader
            } catch (_: ClassNotFoundException) {
                // Continue to next loader
            }
        }
        return null
    }

    /**
     * Remove ClassLoader entries on app uninstall/stop.
     */
    fun unregister(packageName: String, instanceId: String) {
        byPackageName.remove(packageName)
        byInstanceId.remove(instanceId)
        Timber.tag(TAG).d("Unregistered ClassLoader for $packageName ($instanceId)")
    }

    /**
     * Check if a ClassLoader belongs to a guest app.
     */
    fun isGuestClassLoader(classLoader: ClassLoader?): Boolean {
        if (classLoader == null) return false
        return byPackageName.values.any { it === classLoader } ||
               byInstanceId.values.any { it === classLoader }
    }

    fun clear() {
        byPackageName.clear()
        byInstanceId.clear()
    }
}
