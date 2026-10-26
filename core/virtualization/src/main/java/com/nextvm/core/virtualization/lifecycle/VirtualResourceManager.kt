package com.nextvm.core.virtualization.lifecycle

import android.app.Activity
import android.content.Context
import android.content.res.AssetManager
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import android.util.DisplayMetrics
import android.view.WindowManager
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.common.findMethod
import com.nextvm.core.common.runSafe
import org.lsposed.hiddenapibypass.HiddenApiBypass
import timber.log.Timber
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * VirtualResourceManager — REAL Android OS resource loading for guest APKs.
 *
 * Ported from Android 16 frameworks/base:
 *   - ResourcesManager.java → createResources() / createResourcesImpl() / createAssetManager()
 *   - AssetManager.java → Builder.addApkAssets().build() (API 28+) / addAssetPath() (API < 28)
 *   - ApkAssets.java → loadFromPath() factory method (API 28+)
 *   - ResourcesImpl.java → constructor(AssetManager, DisplayMetrics, Configuration, DisplayAdjustments)
 *   - Resources.java → setImpl(ResourcesImpl) to swap implementation
 *   - LoadedApk.java → getResources() flow
 *   - ContextImpl.java → mResources, mPackageInfo (LoadedApk) fields
 *
 * Resource loading flow (replicating what Android does internally):
 *   1. Create ApkAssets for system framework (/system/framework/framework-res.apk)
 *   2. Create ApkAssets for guest APK (+ split APKs if any)
 *   3. Build AssetManager with all ApkAssets
 *   4. Create DisplayMetrics from host display
 *   5. Create Configuration from host + optional overrides
 *   6. Create ResourcesImpl(AssetManager, DisplayMetrics, Configuration, DisplayAdjustments)
 *   7. Create Resources wrapper and set the ResourcesImpl via Resources.setImpl()
 *   8. Inject into ContextImpl.mResources, LoadedApk.mResources, Activity.mResources
 *
 * API level handling:
 *   API < 28 (Oreo-): AssetManager has public constructor + addAssetPath(String)
 *   API 28+  (Pie+):  AssetManager constructor is private, use ApkAssets + Builder
 *   API 30+  (R+):    AssetManager.Builder is the official path
 *
 * CRITICAL: ResourcesImpl.mAssets is FINAL — you CANNOT swap the AssetManager
 * on an existing ResourcesImpl. Must create a new ResourcesImpl entirely and
 * use Resources.setImpl() to inject it.
 */
@Singleton
class VirtualResourceManager @Inject constructor() {

    companion object {
        private const val TAG = "VResources"

        /** System framework resources APK — needed for all Android Resources */
        private const val SYSTEM_FRAMEWORK_APK = "/system/framework/framework-res.apk"

        /** WebView APK path possibilities */
        private val WEBVIEW_APK_PATHS = listOf(
            "/system/app/WebViewGoogle/WebViewGoogle.apk",
            "/system/app/GoogleWebView/GoogleWebView.apk",
            "/product/app/WebViewGoogle/WebViewGoogle.apk",
            "/system/app/webview/webview.apk"
        )
    }

    private var initialized = false
    private lateinit var appContext: Context

    // ─── Caches ────────────────────────────────────────────────

    /**
     * Resource entry per guest app instance — includes AssetManager, Resources,
     * configuration, and split APK tracking.
     */
    data class ResourceEntry(
        val instanceId: String,
        val apkPath: String,
        val assetManager: AssetManager,
        val resources: Resources,
        var configuration: Configuration,
        val splitApkPaths: List<String>
    )

    /** instanceId → ResourceEntry (per-instance isolation) */
    private val resourceCache = ConcurrentHashMap<String, ResourceEntry>()

    /** apkPath → AssetManager (shared across instances of same APK for memory efficiency) */
    private val assetManagerCache = ConcurrentHashMap<String, AssetManager>()

    /** System framework ApkAssets (loaded once, reused for all guest apps) */
    @Volatile
    private var systemFrameworkApkAssets: Any? = null

    // ─── Initialization ────────────────────────────────────────

    fun initialize(context: Context) {
        if (initialized) return
        appContext = context.applicationContext
        initialized = true

        // Pre-cache system framework ApkAssets on API 28+
        if (AndroidCompat.isAtLeastP) {
            preloadSystemFrameworkApkAssets()
        }

        Timber.tag(TAG).i("VirtualResourceManager initialized — Resource loading ready")
    }

    /**
     * Pre-load the system framework ApkAssets for reuse across all guest apps.
     * Avoids repeatedly loading /system/framework/framework-res.apk.
     */
    private fun preloadSystemFrameworkApkAssets() {
        runSafe(TAG) {
            if (!File(SYSTEM_FRAMEWORK_APK).exists()) {
                Timber.tag(TAG).w("System framework APK not found at $SYSTEM_FRAMEWORK_APK")
                return@runSafe
            }
            systemFrameworkApkAssets = loadApkAssets(SYSTEM_FRAMEWORK_APK, isSystem = true)
            Timber.tag(TAG).d("System framework ApkAssets pre-loaded")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PUBLIC API — Create Resources for guest APK
    // ═══════════════════════════════════════════════════════════

    /**
     * Create a complete Resources object for a guest APK.
     *
     * This is the primary entry point. Replicates the full ResourcesManager
     * resource creation pipeline from Android 16.
     *
     * @param context Host context for display metrics and base configuration
     * @param apkPath Full path to the guest APK file
     * @param splitApkPaths Paths to split APKs (dynamic features, etc.)
     * @param libDir Native library directory
     * @param classLoader The guest app's ClassLoader
     * @param instanceId Unique instance ID for caching
     * @return Resources that can load resources from the guest APK
     */
    fun createResourcesForApp(
        context: Context,
        apkPath: String,
        splitApkPaths: List<String>? = null,
        libDir: String? = null,
        classLoader: ClassLoader,
        instanceId: String
    ): Resources? {
        // Check cache first
        val cached = resourceCache[instanceId]
        if (cached != null && cached.apkPath == apkPath) {
            Timber.tag(TAG).d("Returning cached Resources for $instanceId")
            return cached.resources
        }

        Timber.tag(TAG).i("Creating Resources for guest APK: $apkPath (instance=$instanceId)")

        try {
            // Step 1: Create AssetManager with the guest APK + system framework
            val assetManager = createAssetManagerForApp(
                apkPath = apkPath,
                splitApkPaths = splitApkPaths ?: emptyList()
            ) ?: run {
                Timber.tag(TAG).e("Failed to create AssetManager for $apkPath")
                return null
            }

            // Step 2: Get display metrics from host
            val displayMetrics = getDisplayMetrics(context)

            // Step 3: Build configuration from host
            val configuration = Configuration(context.resources.configuration)

            // Step 4: Create ResourcesImpl via reflection
            val resourcesImpl = createResourcesImpl(assetManager, displayMetrics, configuration)

            // Step 5: Create Resources wrapper
            val resources: Resources = if (resourcesImpl != null) {
                // Create Resources and inject our ResourcesImpl
                createResourcesWithImpl(resourcesImpl, classLoader)
                    ?: Resources(assetManager, displayMetrics, configuration) // fallback
            } else {
                // Fallback: use standard Resources constructor (API < 28 style)
                @Suppress("DEPRECATION")
                Resources(assetManager, displayMetrics, configuration)
            }

            // Some optional CM title/bubble dimensions are delivered as resource ID 0
            // by the packed guest. Keep the real guest ResourcesImpl, but make the
            // zero-dimension sentinel harmless instead of crashing layout traversal.
            val compatibleResources = wrapZeroDimensionResources(
                resources, assetManager, displayMetrics, configuration
            )

            // Step 6: Cache
            val splits = splitApkPaths ?: emptyList()
            resourceCache[instanceId] = ResourceEntry(
                instanceId = instanceId,
                apkPath = apkPath,
                assetManager = assetManager,
                resources = compatibleResources,
                configuration = configuration,
                splitApkPaths = splits
            )

            Timber.tag(TAG).i("Resources created for $apkPath (density=${displayMetrics.densityDpi}, " +
                "locale=${configuration.locales.get(0)}, splits=${splits.size})")
            return compatibleResources

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to create Resources for $apkPath")
            return null
        }
    }
    /**
     * Resources subclass used only for the guest resource instance.
     * Resource ID 0 is invalid for normal Android Resources, but this packed
     * guest uses it for optional CM UI dimensions. Returning 0 preserves the
     * optional UI's intended default without hiding unrelated resource errors.
     */
    private class ZeroDimensionResources(
        assetManager: AssetManager,
        displayMetrics: DisplayMetrics,
        configuration: Configuration
    ) : Resources(assetManager, displayMetrics, configuration) {
        override fun getDimensionPixelSize(id: Int): Int {
            if (id == 0) return 0
            return super.getDimensionPixelSize(id)
        }

        override fun getDimension(id: Int): Float {
            if (id == 0) return 0f
            return super.getDimension(id)
        }
    }

    private fun wrapZeroDimensionResources(
        resources: Resources,
        assetManager: AssetManager,
        displayMetrics: DisplayMetrics,
        configuration: Configuration
    ): Resources {
        val compatible = ZeroDimensionResources(assetManager, displayMetrics, configuration)
        runCatching {
            // Preserve the already-created guest ResourcesImpl, including its
            // ApkAssets and configuration-specific caches.
            val implField = findField(Resources::class.java, "mResourcesImpl")
            implField?.isAccessible = true
            implField?.set(compatible, implField?.get(resources))
            val classLoaderField = findField(Resources::class.java, "mClassLoader")
            classLoaderField?.isAccessible = true
            classLoaderField?.set(compatible, classLoaderField?.get(resources))
        }.onFailure {
            Timber.tag(TAG).w(it, "Could not copy guest Resources internals into compatibility wrapper")
        }
        return compatible
    }

    /**
     * Simplified createResources for backward compatibility.
     */
    fun createResources(apkPath: String, context: Context, instanceId: String? = null): Resources? {
        return createResourcesForApp(
            context = context,
            apkPath = apkPath,
            splitApkPaths = null,
            libDir = null,
            classLoader = context.classLoader,
            instanceId = instanceId ?: apkPath.hashCode().toString()
        )
    }

    // ═══════════════════════════════════════════════════════════
    // ASSET MANAGER CREATION — The Core of Resource Loading
    // ═══════════════════════════════════════════════════════════

    /**
     * Create an AssetManager that can load assets from the guest APK.
     *
     * Three strategies based on API level:
     * - API < 28: Public constructor + addAssetPath()
     * - API 28-29: ApkAssets.loadFromPath() + setApkAssets()
     * - API 30+: AssetManager.Builder (preferred path in Android 16)
     */
    private fun createAssetManagerForApp(
        apkPath: String,
        splitApkPaths: List<String>
    ): AssetManager? {
        val cacheKey = buildCacheKey(apkPath, splitApkPaths)
        assetManagerCache[cacheKey]?.let {
            Timber.tag(TAG).d("Returning cached AssetManager for $apkPath")
            return it
        }

        val assetManager = when {
            Build.VERSION.SDK_INT >= 30 -> createAssetManagerViaBuilder(apkPath, splitApkPaths)
            Build.VERSION.SDK_INT >= 28 -> createAssetManagerViaApkAssets(apkPath, splitApkPaths)
            else -> createAssetManagerLegacy(apkPath, splitApkPaths)
        }

        if (assetManager != null) {
            assetManagerCache[cacheKey] = assetManager
        }

        return assetManager
    }

    /**
     * API 30+ (Android R+): Use AssetManager.Builder
     *
     * From Android 16 AssetManager.java:
     *   public static class Builder {
     *     public Builder addApkAssets(ApkAssets apkAssets) { ... }
     *     public AssetManager build() { ... }
     *   }
     */
    private fun createAssetManagerViaBuilder(
        apkPath: String,
        splitApkPaths: List<String>
    ): AssetManager? {
        return runSafe(TAG) {
            Timber.tag(TAG).d("Creating AssetManager via Builder (API 30+)")

            val builderClass = Class.forName("android.content.res.AssetManager\$Builder")
            val builderCtor = builderClass.getDeclaredConstructor()
            builderCtor.isAccessible = true
            val builder = builderCtor.newInstance()

            val apkAssetsClass = Class.forName("android.content.res.ApkAssets")
            val addApkAssetsMethod = findMethod(builderClass, "addApkAssets",
                arrayOf(apkAssetsClass))
                ?: throw IllegalStateException("AssetManager.Builder.addApkAssets() not found")
            addApkAssetsMethod.isAccessible = true

            val buildMethod = findMethod(builderClass, "build", emptyArray())
                ?: throw IllegalStateException("AssetManager.Builder.build() not found")
            buildMethod.isAccessible = true

            // 1. Add system framework resources first
            val sysApkAssets = systemFrameworkApkAssets
                ?: loadApkAssets(SYSTEM_FRAMEWORK_APK, isSystem = true)
            if (sysApkAssets != null) {
                addApkAssetsMethod.invoke(builder, sysApkAssets)
            }

            // 2. Add the guest APK
            val guestApkAssets = loadApkAssets(apkPath, isSystem = false)
                ?: throw IllegalStateException("Failed to load ApkAssets for $apkPath")
            addApkAssetsMethod.invoke(builder, guestApkAssets)

            // 3. Add split APKs
            for (splitPath in splitApkPaths) {
                val splitApkAssets = loadApkAssets(splitPath, isSystem = false)
                if (splitApkAssets != null) {
                    addApkAssetsMethod.invoke(builder, splitApkAssets)
                    Timber.tag(TAG).d("Added split APK: $splitPath")
                }
            }

            // 4. Build the AssetManager
            val assetManager = buildMethod.invoke(builder) as AssetManager
            Timber.tag(TAG).d("AssetManager built via Builder (${2 + splitApkPaths.size} assets)")
            assetManager
        }
    }

    /**
     * API 28-29 (Android P-Q): Use ApkAssets + setApkAssets()
     *
     * From Android 16 AssetManager.java:
     *   void setApkAssets(@NonNull ApkAssets[] apkAssets, boolean invalidateCaches)
     */
    private fun createAssetManagerViaApkAssets(
        apkPath: String,
        splitApkPaths: List<String>
    ): AssetManager? {
        return runSafe(TAG) {
            Timber.tag(TAG).d("Creating AssetManager via setApkAssets (API 28-29)")

            // Create empty AssetManager via hidden constructor
            val amClass = AssetManager::class.java
            val ctor = amClass.getDeclaredConstructor()
            ctor.isAccessible = true
            val assetManager = ctor.newInstance()

            // Collect all ApkAssets
            val apkAssetsList = mutableListOf<Any>()

            // 1. Get system framework ApkAssets from the existing system AssetManager
            val systemApkAssets = getSystemApkAssets()
            apkAssetsList.addAll(systemApkAssets)

            // 2. Load guest APK ApkAssets
            val guestApkAssets = loadApkAssets(apkPath, isSystem = false)
                ?: throw IllegalStateException("Failed to load ApkAssets for $apkPath")
            apkAssetsList.add(guestApkAssets)

            // 3. Load split APKs
            for (splitPath in splitApkPaths) {
                val splitApkAssets = loadApkAssets(splitPath, isSystem = false)
                if (splitApkAssets != null) {
                    apkAssetsList.add(splitApkAssets)
                }
            }

            // 4. Call setApkAssets
            val apkAssetsArrayClass = Class.forName("[Landroid.content.res.ApkAssets;")
            val setApkAssetsMethod = findMethod(amClass, "setApkAssets",
                arrayOf(apkAssetsArrayClass, Boolean::class.javaPrimitiveType!!))

            if (setApkAssetsMethod != null) {
                setApkAssetsMethod.isAccessible = true
                val apkAssetsType = Class.forName("android.content.res.ApkAssets")
                val array = java.lang.reflect.Array.newInstance(apkAssetsType, apkAssetsList.size)
                apkAssetsList.forEachIndexed { i, asset ->
                    java.lang.reflect.Array.set(array, i, asset)
                }
                setApkAssetsMethod.invoke(assetManager, array, true)
                Timber.tag(TAG).d("setApkAssets called with ${apkAssetsList.size} assets")
            } else {
                throw IllegalStateException("setApkAssets method not found")
            }

            assetManager
        }
    }

    /**
     * API < 28 (Android O and below): Use public constructor + addAssetPath()
     *
     * AssetManager() is publicly constructable before API 28.
     * addAssetPath(String) is a hidden API but not restricted pre-P.
     */
    private fun createAssetManagerLegacy(
        apkPath: String,
        splitApkPaths: List<String>
    ): AssetManager? {
        return runSafe(TAG) {
            Timber.tag(TAG).d("Creating AssetManager via addAssetPath (API < 28)")

            val amClass = AssetManager::class.java
            val ctor = amClass.getDeclaredConstructor()
            ctor.isAccessible = true
            val assetManager = ctor.newInstance()

            val addAssetPath = findMethod(amClass, "addAssetPath", arrayOf(String::class.java))
                ?: throw IllegalStateException("addAssetPath not found")
            addAssetPath.isAccessible = true

            // 1. Add system framework resources
            if (File(SYSTEM_FRAMEWORK_APK).exists()) {
                val cookie = addAssetPath.invoke(assetManager, SYSTEM_FRAMEWORK_APK) as? Int
                Timber.tag(TAG).d("Added system framework, cookie=$cookie")
            }

            // 2. Add guest APK
            val guestCookie = addAssetPath.invoke(assetManager, apkPath) as? Int
            if (guestCookie == null || guestCookie == 0) {
                // Try addAssetPathAsSharedLibrary as fallback
                val addAsSharedLib = findMethod(amClass, "addAssetPathAsSharedLibrary",
                    arrayOf(String::class.java))
                if (addAsSharedLib != null) {
                    addAsSharedLib.isAccessible = true
                    addAsSharedLib.invoke(assetManager, apkPath)
                    Timber.tag(TAG).d("Used addAssetPathAsSharedLibrary fallback")
                } else {
                    throw IllegalStateException("addAssetPath failed for $apkPath")
                }
            } else {
                Timber.tag(TAG).d("Added guest APK, cookie=$guestCookie")
            }

            // 3. Add split APKs
            for (splitPath in splitApkPaths) {
                val splitCookie = addAssetPath.invoke(assetManager, splitPath) as? Int
                Timber.tag(TAG).d("Added split APK $splitPath, cookie=$splitCookie")
            }

            assetManager
        }
    }

    // ═══════════════════════════════════════════════════════════
    // ApkAssets — API 28+
    // ═══════════════════════════════════════════════════════════

    /**
     * Load ApkAssets from a file path.
     *
     * From Android 16 ApkAssets.java:
     *   public static ApkAssets loadFromPath(@NonNull String path)
     *   public static ApkAssets loadFromPath(@NonNull String path, @PropertyFlags int flags)
     *
     * Property flags: PROPERTY_SYSTEM = 1 << 0
     */
    private fun loadApkAssets(path: String, isSystem: Boolean = false): Any? {
        return runSafe(TAG) {
            val apkAssetsClass = Class.forName("android.content.res.ApkAssets")

            // Try loadFromPath(String, int) first (has flags parameter)
            val loadFromPathWithFlags = runSafe(TAG) {
                findMethod(apkAssetsClass, "loadFromPath",
                    arrayOf(String::class.java, Int::class.javaPrimitiveType!!))
            }

            if (loadFromPathWithFlags != null) {
                loadFromPathWithFlags.isAccessible = true
                val flags = if (isSystem) 1 else 0
                return@runSafe loadFromPathWithFlags.invoke(null, path, flags)
            }

            // Fallback: loadFromPath(String) without flags
            val loadFromPath = findMethod(apkAssetsClass, "loadFromPath",
                arrayOf(String::class.java))
            if (loadFromPath != null) {
                loadFromPath.isAccessible = true
                return@runSafe loadFromPath.invoke(null, path)
            }

            // Last resort: try constructor
            val ctor = runSafe(TAG) {
                apkAssetsClass.getDeclaredConstructor(
                    String::class.java, Boolean::class.javaPrimitiveType!!)
            }
            if (ctor != null) {
                ctor.isAccessible = true
                return@runSafe ctor.newInstance(path, isSystem)
            }

            // LSPosed HiddenApiBypass: invoke hidden methods when standard reflection is blocked
            if (Build.VERSION.SDK_INT >= 28) {
                Timber.tag(TAG).d("Standard reflection failed for ApkAssets, trying HiddenApiBypass...")
                
                // Try loadFromPath(String, int) via HiddenApiBypass
                val resultWithFlags = runSafe(TAG) {
                    val flags = if (isSystem) 1 else 0
                    HiddenApiBypass.invoke(apkAssetsClass, null, "loadFromPath", path, flags)
                }
                if (resultWithFlags != null) {
                    Timber.tag(TAG).d("ApkAssets created via HiddenApiBypass.invoke(loadFromPath, String, int)")
                    return@runSafe resultWithFlags
                }

                // Try loadFromPath(String) via HiddenApiBypass
                val resultNoFlags = runSafe(TAG) {
                    HiddenApiBypass.invoke(apkAssetsClass, null, "loadFromPath", path)
                }
                if (resultNoFlags != null) {
                    Timber.tag(TAG).d("ApkAssets created via HiddenApiBypass.invoke(loadFromPath, String)")
                    return@runSafe resultNoFlags
                }

                // Try constructor via HiddenApiBypass
                val ctorResult = runSafe(TAG) {
                    HiddenApiBypass.newInstance(apkAssetsClass, path, isSystem)
                }
                if (ctorResult != null) {
                    Timber.tag(TAG).d("ApkAssets created via HiddenApiBypass.newInstance()")
                    return@runSafe ctorResult
                }
            }

            Timber.tag(TAG).e("Cannot create ApkAssets for $path — no method available (including HiddenApiBypass)")
            null
        }
    }

    /**
     * Get the system ApkAssets from the existing system Resources.
     *
     * From Android 16 AssetManager.java:
     *   public @NonNull ApkAssets[] getApkAssets() { ... }
     */
    private fun getSystemApkAssets(): List<Any> {
        return runSafe(TAG) {
            val systemResources = Resources.getSystem()
            val systemAssets = systemResources.assets

            val getApkAssetsMethod = findMethod(AssetManager::class.java, "getApkAssets", emptyArray())
            if (getApkAssetsMethod != null) {
                getApkAssetsMethod.isAccessible = true
                val apkAssetsArray = getApkAssetsMethod.invoke(systemAssets)
                if (apkAssetsArray != null && apkAssetsArray::class.java.isArray) {
                    val length = java.lang.reflect.Array.getLength(apkAssetsArray)
                    Timber.tag(TAG).d("System has $length ApkAssets entries")
                    return@runSafe (0 until length).map { i ->
                        java.lang.reflect.Array.get(apkAssetsArray, i)
                    }
                }
            }

            // Fallback: use the pre-loaded system framework ApkAssets
            val sys = systemFrameworkApkAssets
            if (sys != null) return@runSafe listOf(sys)

            emptyList()
        } ?: emptyList()
    }

    // ═══════════════════════════════════════════════════════════
    // ResourcesImpl — The Real Implementation
    // ═══════════════════════════════════════════════════════════

    /**
     * Create a ResourcesImpl via reflection.
     *
     * From Android 16 ResourcesImpl.java:
     *   public ResourcesImpl(@NonNull AssetManager assets,
     *                        @Nullable DisplayMetrics metrics,
     *                        @Nullable Configuration config,
     *                        @NonNull DisplayAdjustments daj)
     *
     * ResourcesImpl.mAssets is FINAL — once created, cannot swap.
     * Must create a new ResourcesImpl for each unique AssetManager.
     */
    private fun createResourcesImpl(
        assetManager: AssetManager,
        displayMetrics: DisplayMetrics,
        configuration: Configuration
    ): Any? {
        return runSafe(TAG) {
            val resourcesImplClass = Class.forName("android.content.res.ResourcesImpl")

            // Get DisplayAdjustments — needed for compat mode
            val displayAdjustmentsClass = Class.forName("android.view.DisplayAdjustments")
            val dajCtor = displayAdjustmentsClass.getDeclaredConstructor()
            dajCtor.isAccessible = true
            val displayAdjustments = dajCtor.newInstance()

            // Find the 4-param constructor
            val implCtor = resourcesImplClass.getDeclaredConstructor(
                AssetManager::class.java,
                DisplayMetrics::class.java,
                Configuration::class.java,
                displayAdjustmentsClass
            )
            implCtor.isAccessible = true

            val impl = implCtor.newInstance(assetManager, displayMetrics, configuration, displayAdjustments)
            Timber.tag(TAG).d("ResourcesImpl created successfully")
            impl
        }
    }

    /**
     * Create a Resources object and inject our custom ResourcesImpl.
     *
     * From Android 16 Resources.java:
     *   public void setImpl(ResourcesImpl impl) { ... }
     *
     * We create a dummy Resources first, then swap its impl.
     */
    private fun createResourcesWithImpl(resourcesImpl: Any, classLoader: ClassLoader): Resources? {
        return runSafe(TAG) {
            // Create base Resources from system (it has a valid native pointer)
            val baseResources = Resources.getSystem()
            @Suppress("DEPRECATION")
            val resources = Resources(baseResources.assets, baseResources.displayMetrics,
                baseResources.configuration)

            // Use setImpl to inject our ResourcesImpl
            val resourcesImplClass = Class.forName("android.content.res.ResourcesImpl")
            val setImplMethod = findMethod(Resources::class.java, "setImpl",
                arrayOf(resourcesImplClass))

            if (setImplMethod != null) {
                setImplMethod.isAccessible = true
                setImplMethod.invoke(resources, resourcesImpl)
                Timber.tag(TAG).d("ResourcesImpl injected via setImpl()")
            } else {
                // Fallback: set mResourcesImpl field directly
                val implField = findField(Resources::class.java, "mResourcesImpl")
                if (implField != null) {
                    implField.isAccessible = true
                    implField.set(resources, resourcesImpl)
                    Timber.tag(TAG).d("ResourcesImpl injected via field reflection")
                }
            }

            // NOTE: Resources.setClassLoader() does NOT exist on API 34+.
            // ClassLoader binding is handled at the LoadedApk level by
            // VirtualClassLoaderInjector, so we skip calling it here.

            resources
        }
    }

    // ═══════════════════════════════════════════════════════════
    // INJECTION — Set guest Resources on Activity/Context
    // ═══════════════════════════════════════════════════════════

    /**
     * Inject guest Resources into an Activity's context hierarchy.
     *
     * Replaces resources at ALL levels:
     *   1. Activity.mResources (ContextThemeWrapper)
     *   2. Activity.mBase (ContextImpl).mResources
     *   3. Activity.mBase.mPackageInfo (LoadedApk).mResources
     *   4. Force theme re-creation by nulling mTheme
     */
    fun injectResourcesIntoActivity(activity: Activity, resources: Resources) {
        try {
            // 1. Replace mResources on ContextThemeWrapper (Activity's superclass)
            val ctw = android.view.ContextThemeWrapper::class.java
            val mResourcesField = findField(ctw, "mResources")
            if (mResourcesField != null) {
                mResourcesField.isAccessible = true
                mResourcesField.set(activity, resources)
                Timber.tag(TAG).d("Injected into ContextThemeWrapper.mResources")
            }

            // 2. Force theme re-creation by nulling mTheme
            val mThemeField = findField(ctw, "mTheme")
            if (mThemeField != null) {
                mThemeField.isAccessible = true
                mThemeField.set(activity, null)
                Timber.tag(TAG).d("Nulled ContextThemeWrapper.mTheme for re-creation")
            }

            // 3. Replace on the base ContextImpl
            val baseContext = activity.baseContext
            if (baseContext != null) {
                injectResourcesIntoContext(baseContext, resources)
            }

            Timber.tag(TAG).i("Resources injected into Activity successfully")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to inject Resources into Activity")
        }
    }

    /**
     * Inject guest Resources into a Context (typically ContextImpl).
     *
     * From Android 16 ContextImpl.java:
     *   private Resources mResources
     *   private LoadedApk mPackageInfo
     */
    fun injectResourcesIntoContext(context: Context, resources: Resources) {
        try {
            val contextClass = context.javaClass

            // ContextImpl.mResources
            val mResources = findField(contextClass, "mResources")
            if (mResources != null) {
                mResources.isAccessible = true
                mResources.set(context, resources)
                Timber.tag(TAG).d("Injected into ContextImpl.mResources")
            }

            // ContextImpl.mPackageInfo (LoadedApk) → LoadedApk.mResources
            val mPackageInfo = findField(contextClass, "mPackageInfo")
            if (mPackageInfo != null) {
                mPackageInfo.isAccessible = true
                val loadedApk = mPackageInfo.get(context)
                if (loadedApk != null) {
                    val loadedApkResources = findField(loadedApk.javaClass, "mResources")
                    if (loadedApkResources != null) {
                        loadedApkResources.isAccessible = true
                        loadedApkResources.set(loadedApk, resources)
                        Timber.tag(TAG).d("Injected into LoadedApk.mResources")
                    }
                }
            }

            // Null the theme so it gets recreated with guest resources
            val mTheme = findField(contextClass, "mTheme")
            if (mTheme != null) {
                mTheme.isAccessible = true
                mTheme.set(context, null)
            }

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to inject Resources into Context")
        }
    }

    /**
     * Inject Resources into ActivityThread's mPackages map for a package name.
     *
     * From Android 16 ActivityThread.java:
     *   final ArrayMap<String, WeakReference<LoadedApk>> mPackages
     */
    fun injectResourcesIntoActivityThread(packageName: String, resources: Resources) {
        runSafe(TAG) {
            val atClass = Class.forName("android.app.ActivityThread")
            val currentATMethod = atClass.getDeclaredMethod("currentActivityThread")
            currentATMethod.isAccessible = true
            val activityThread = currentATMethod.invoke(null) ?: return@runSafe

            val mPackagesField = findField(atClass, "mPackages")
            if (mPackagesField != null) {
                mPackagesField.isAccessible = true
                @Suppress("UNCHECKED_CAST")
                val mPackages = mPackagesField.get(activityThread) as? Map<String, Any>
                if (mPackages != null) {
                    val weakRef = mPackages[packageName]
                    if (weakRef != null) {
                        // WeakReference.get() is inherited from a public JDK class;
                        // looking it up on the concrete class with getDeclaredMethod
                        // fails on Android and makes this injection silently no-op.
                        val loadedApk = (weakRef as? java.lang.ref.WeakReference<*>)?.get()
                        if (loadedApk != null) {
                            val resField = findField(loadedApk.javaClass, "mResources")
                            if (resField != null) {
                                resField.isAccessible = true
                                resField.set(loadedApk, resources)
                                Timber.tag(TAG).d("Injected into ActivityThread.mPackages[$packageName]")
                            }
                        }
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // THEME APPLICATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Apply a theme from the guest APK to an Activity.
     *
     * 1. Inject guest Resources into the Activity
     * 2. Apply the theme resource from the guest APK's Resources
     * 3. Force window background from the applied theme
     *
     * @param activity The Activity to theme
     * @param themeResId Theme resource ID from the guest APK's manifest
     * @param resources Guest APK's Resources (from createResourcesForApp)
     */
    fun applyTheme(activity: Activity, themeResId: Int, resources: Resources) {
        try {
            // 1. Inject resources first
            injectResourcesIntoActivity(activity, resources)

            // 2. Apply theme
            if (themeResId != 0) {
                activity.setTheme(themeResId)
                Timber.tag(TAG).d("Applied theme: 0x${themeResId.toString(16)}")
            } else {
                // Safe default theme
                activity.setTheme(android.R.style.Theme_DeviceDefault_Light_DarkActionBar)
                Timber.tag(TAG).d("Applied default theme (no guest theme specified)")
            }

            // 3. Force window background from theme
            runSafe(TAG) {
                val window = activity.window
                val typedArray = activity.obtainStyledAttributes(
                    intArrayOf(android.R.attr.windowBackground)
                )
                val backgroundDrawable = typedArray.getDrawable(0)
                typedArray.recycle()
                if (backgroundDrawable != null) {
                    window.setBackgroundDrawable(backgroundDrawable)
                }
            }

        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to apply theme 0x${themeResId.toString(16)}")
        }
    }

    /**
     * Resolve a theme resource ID from the guest APK's manifest.
     *
     * Activity-specific theme takes precedence over app-level theme.
     *
     * @param resources Guest app's Resources
     * @param appThemeResId Theme from ApplicationInfo.theme
     * @param activityThemeResId Theme from ActivityInfo.getThemeResource()
     * @return The resolved theme resource ID
     */
    fun resolveThemeResId(
        resources: Resources,
        appThemeResId: Int,
        activityThemeResId: Int
    ): Int {
        // Activity-specific theme takes precedence
        if (activityThemeResId != 0 && isValidResourceId(resources, activityThemeResId)) {
            return activityThemeResId
        }

        // Application-level theme
        if (appThemeResId != 0 && isValidResourceId(resources, appThemeResId)) {
            return appThemeResId
        }

        // Default fallback
        return android.R.style.Theme_DeviceDefault_Light_DarkActionBar
    }

    /**
     * Check if a resource ID is valid in the given Resources.
     */
    private fun isValidResourceId(resources: Resources, resId: Int): Boolean {
        return runSafe(TAG) {
            resources.getResourceTypeName(resId)
            true
        } ?: false
    }

    // ═══════════════════════════════════════════════════════════
    // WebView RESOURCE COMPATIBILITY
    // ═══════════════════════════════════════════════════════════

    /**
     * Ensure WebView can find its resources when running inside a guest app.
     * WebView loads resources from its own APK, which may not be in our AssetManager.
     */
    fun ensureWebViewResources(instanceId: String) {
        val entry = resourceCache[instanceId] ?: return

        runSafe(TAG) {
            val webViewPath = WEBVIEW_APK_PATHS.firstOrNull { File(it).exists() }
            if (webViewPath != null) {
                val addAssetPath = findMethod(AssetManager::class.java, "addAssetPath",
                    arrayOf(String::class.java))
                if (addAssetPath != null) {
                    addAssetPath.isAccessible = true
                    addAssetPath.invoke(entry.assetManager, webViewPath)
                    Timber.tag(TAG).d("Added WebView resources: $webViewPath")
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // CONFIGURATION UPDATES
    // ═══════════════════════════════════════════════════════════

    /**
     * Update configuration for a guest app's Resources.
     * Called when system configuration changes (orientation, locale, dark mode).
     */
    fun updateConfiguration(instanceId: String, newConfig: Configuration) {
        val entry = resourceCache[instanceId] ?: run {
            Timber.tag(TAG).w("No Resources cache entry for $instanceId")
            return
        }

        try {
            val displayMetrics = entry.resources.displayMetrics

            // Create new ResourcesImpl with updated config
            // (reuse the same AssetManager since mAssets is final)
            val newImpl = createResourcesImpl(entry.assetManager, displayMetrics, newConfig)
            if (newImpl != null) {
                val resourcesImplClass = Class.forName("android.content.res.ResourcesImpl")
                val setImplMethod = findMethod(Resources::class.java, "setImpl",
                    arrayOf(resourcesImplClass))
                if (setImplMethod != null) {
                    setImplMethod.isAccessible = true
                    setImplMethod.invoke(entry.resources, newImpl)
                    Timber.tag(TAG).d("Updated ResourcesImpl for $instanceId")
                }
            } else {
                // Fallback: use updateConfiguration
                @Suppress("DEPRECATION")
                entry.resources.updateConfiguration(newConfig, displayMetrics)
            }

            entry.configuration = Configuration(newConfig)
            Timber.tag(TAG).d("Configuration updated for $instanceId")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to update configuration for $instanceId")
        }
    }

    /**
     * Update configuration for Resources by direct reference.
     */
    fun updateConfiguration(resources: Resources, config: Configuration) {
        try {
            @Suppress("DEPRECATION")
            resources.updateConfiguration(config, resources.displayMetrics)
            Timber.tag(TAG).d("Configuration updated on Resources object")
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to update Resources configuration")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // DISPLAY METRICS
    // ═══════════════════════════════════════════════════════════

    /**
     * Get display metrics from the host context.
     */
    private fun getDisplayMetrics(context: Context): DisplayMetrics {
        val dm = DisplayMetrics()
        try {
            val wm = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
            if (wm != null) {
                @Suppress("DEPRECATION")
                wm.defaultDisplay.getRealMetrics(dm)
            } else {
                dm.setToDefaults()
            }
        } catch (e: Exception) {
            Timber.tag(TAG).w(e, "Failed to get display metrics, using defaults")
            dm.setToDefaults()
        }
        return dm
    }

    /**
     * Create display metrics with custom DPI for device spoofing.
     */
    fun createSpoofedDisplayMetrics(context: Context, targetDpi: Int): DisplayMetrics {
        val dm = getDisplayMetrics(context)
        dm.densityDpi = targetDpi
        dm.density = targetDpi / 160f
        dm.scaledDensity = targetDpi / 160f
        return dm
    }

    // ═══════════════════════════════════════════════════════════
    // CACHE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    private fun buildCacheKey(apkPath: String, splitPaths: List<String>): String {
        return if (splitPaths.isEmpty()) apkPath
        else "$apkPath|${splitPaths.sorted().joinToString("|")}"
    }

    /** Get cached Resources for an instance */
    fun getResources(instanceId: String): Resources? =
        resourceCache[instanceId]?.resources

    /** Get cached AssetManager for an APK path */
    fun getAssetManager(apkPath: String): AssetManager? =
        assetManagerCache[apkPath]

    /** Release resources for an instance */
    fun releaseResources(instanceId: String) {
        resourceCache.remove(instanceId)
        Timber.tag(TAG).d("Released Resources for $instanceId")
    }

    /** Release AssetManager for an APK (only when no instances use it) */
    fun releaseAssetManager(apkPath: String) {
        val activeUsers = resourceCache.values.count { it.apkPath == apkPath }
        if (activeUsers == 0) {
            val am = assetManagerCache.remove(apkPath)
            if (am != null) {
                try { am.close() } catch (_: Exception) {}
                Timber.tag(TAG).d("AssetManager released for $apkPath")
            }
        }
    }

    /** Release all cached resources and asset managers */
    fun releaseAll() {
        Timber.tag(TAG).i("Releasing all Resources (${resourceCache.size} entries)")
        resourceCache.clear()
        for ((_, am) in assetManagerCache) {
            try { am.close() } catch (_: Exception) {}
        }
        assetManagerCache.clear()
    }
}
