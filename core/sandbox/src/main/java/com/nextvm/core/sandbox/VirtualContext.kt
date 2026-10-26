package com.nextvm.core.sandbox

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import com.nextvm.core.model.VirtualConstants
import timber.log.Timber
import java.io.File

/**
 * VirtualContext — ContextWrapper that redirects all file I/O to the sandbox.
 *
 * When a guest app calls context.getFilesDir(), context.getCacheDir(), etc.,
 * this wrapper returns sandboxed paths instead of the real ones.
 *
 * Also overrides getPackageName() to return the guest app's package name
 * so the app thinks it's running as its original identity.
 */
class VirtualContext(
    base: Context,
    private val instanceId: String,
    private val guestPackageName: String,
    private val sandboxManager: SandboxManager
) : ContextWrapper(base) {

    private val appDir: File = sandboxManager.getAppDir(instanceId)

    /** Cached meta-data bundle from guest APK (parsed once) */
    private var cachedGuestMetaData: android.os.Bundle? = null

    /**
     * Cache the real base context (unwrapped) to prevent infinite delegation loops.
     * When VirtualContext wraps an Activity (itself a ContextWrapper), methods like
     * getDisplay() / getDisplayNoVerify() can recurse infinitely through the
     * ContextWrapper chain. We unwrap once at construction to break the loop.
     */
    private val realBaseContext: Context = run {
        var ctx: Context = base
        while (ctx is ContextWrapper && ctx !is android.app.Application) {
            val inner = ctx.baseContext ?: break
            if (inner === ctx) break  // self-reference guard
            ctx = inner
        }
        ctx
    }

    // === Display fix — prevents StackOverflowError ===

    @SuppressLint("NewApi")
    override fun getDisplay(): android.view.Display? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                realBaseContext.display
            } else {
                @Suppress("DEPRECATION")
                val wm = realBaseContext.getSystemService(WINDOW_SERVICE) as? android.view.WindowManager
                @Suppress("DEPRECATION")
                wm?.defaultDisplay
            }
        } catch (_: Exception) {
            // Fallback: get default display from WindowManager
            try {
                val wm = realBaseContext.getSystemService(WINDOW_SERVICE) as? android.view.WindowManager
                @Suppress("DEPRECATION")
                wm?.defaultDisplay
            } catch (_: Exception) { null }
        }
    }

    override fun getSystemService(name: String): Any? {
        // Prevent recursive getDisplay() through service lookup
        if (name == DISPLAY_SERVICE || name == WINDOW_SERVICE) {
            return realBaseContext.getSystemService(name)
        }
        return super.getSystemService(name)
    }

    // === File system overrides ===

    override fun getFilesDir(): File =
        sandboxManager.getFilesDir(instanceId)

    override fun getCacheDir(): File =
        sandboxManager.getCacheDir(instanceId)

    override fun getCodeCacheDir(): File =
        sandboxManager.getCodeCacheDir(instanceId)

    override fun getDatabasePath(name: String): File {
        // Match framework behavior: absolute paths are returned as-is
        if (name.startsWith(File.separator)) return File(name)
        return File(sandboxManager.getDatabasesDir(instanceId), name)
    }

    override fun getDir(name: String, mode: Int): File =
        File(appDir, "app_$name").also { it.mkdirs() }

    override fun getExternalFilesDir(type: String?): File {
        return sandboxManager.getExternalAppFilesDir(instanceId, guestPackageName, type)
    }

    override fun getExternalFilesDirs(type: String?): Array<File> {
        return arrayOf(getExternalFilesDir(type))
    }

    override fun getExternalCacheDir(): File =
        sandboxManager.getExternalAppCacheDir(instanceId, guestPackageName)

    override fun getExternalCacheDirs(): Array<File> {
        return arrayOf(externalCacheDir)
    }

    @Suppress("DEPRECATION")
    override fun getExternalMediaDirs(): Array<File> {
        return arrayOf(sandboxManager.getExternalMediaDir(instanceId, guestPackageName))
    }

    override fun getObbDir(): File =
        sandboxManager.getExternalObbDir(instanceId, guestPackageName)

    override fun getObbDirs(): Array<File> {
        return arrayOf(obbDir)
    }

    override fun getNoBackupFilesDir(): File =
        File(appDir, "no_backup").also { it.mkdirs() }

    override fun getDataDir(): File = appDir

    // === SharedPreferences override ===

    override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences {
        // Android's ContextImpl.makeFilename() throws IllegalArgumentException if name
        // contains a path separator ('/').  The old code prepended the full sandbox path
        // which always contained '/'.
        //
        // Strategy: Flatten the name to a safe per-instance key (no '/' chars) and let
        // the base ContextImpl store it in the HOST's shared_prefs directory.  The
        // per-instance prefix ensures isolation between guest apps.
        //
        // Resulting files live under:
        //   /data/data/com.nextvm.app/shared_prefs/nextvm_{instanceId}_{name}.xml
        val safeName = name ?: "default"
        val isolatedName = "nextvm_${instanceId}_${safeName.replace('/', '_').replace('\\', '_')}"
        return super.getSharedPreferences(isolatedName, mode)
    }

    // === Identity overrides ===

    override fun getPackageName(): String = guestPackageName

    /**
     * Binder services validate the operation package against the host UID.
     * Keep getPackageName() virtual for guest code, but use the host identity
     * for framework operations such as Toast windows.
     */
    override fun getOpPackageName(): String = VirtualConstants.HOST_PACKAGE

    override fun getApplicationInfo(): ApplicationInfo {
        return super.getApplicationInfo().apply {
            packageName = guestPackageName
            dataDir = appDir.absolutePath
            nativeLibraryDir = sandboxManager.getLibDir(instanceId).absolutePath
            // Set sourceDir/publicSourceDir to the guest APK so that ReLinker,
            // GMS, and other libraries that read sourceDir to find native libs
            // or resources in the APK can locate the correct file.
            val guestApkPath = sandboxManager.getApkPath(instanceId)
            if (guestApkPath != null) {
                sourceDir = guestApkPath
                publicSourceDir = guestApkPath
            }

            // Inject guest APK's meta-data so SDKs (GMS, Firebase, AppLovin)
            // can read their <meta-data> tags. Without this, GMS throws
            // GooglePlayServicesMissingManifestValueException.
            // Use cached bundle to avoid re-parsing the APK on every call.
            val cached = cachedGuestMetaData
            if (cached != null) {
                metaData = cached
            } else if (guestApkPath != null) {
                try {
                    val pm = baseContext.packageManager
                    val pkgInfo = pm.getPackageArchiveInfo(
                        guestApkPath,
                        android.content.pm.PackageManager.GET_META_DATA
                    )
                    pkgInfo?.applicationInfo?.let { guestInfo ->
                        guestInfo.sourceDir = guestApkPath
                        guestInfo.publicSourceDir = guestApkPath
                    }
                    val guestMeta = pkgInfo?.applicationInfo?.metaData ?: android.os.Bundle()
                    // Ensure GMS version is always present
                    if (!guestMeta.containsKey("com.google.android.gms.version")) {
                        guestMeta.putInt("com.google.android.gms.version", 243431006)
                    }
                    cachedGuestMetaData = guestMeta
                    metaData = guestMeta
                } catch (_: Exception) {
                    val fallback = android.os.Bundle().apply {
                        putInt("com.google.android.gms.version", 243431006)
                    }
                    cachedGuestMetaData = fallback
                    metaData = fallback
                }
            }
        }
    }

    override fun getPackageManager(): PackageManager {
        // Return the real PackageManager — our IPackageManager proxy handles
        // intercepting calls for virtual packages
        return super.getPackageManager()
    }

    // === Database overrides ===

    override fun openOrCreateDatabase(
        name: String,
        mode: Int,
        factory: android.database.sqlite.SQLiteDatabase.CursorFactory?
    ): android.database.sqlite.SQLiteDatabase {
        val dbPath = getDatabasePath(name)
        dbPath.parentFile?.mkdirs()
        return android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(dbPath, factory)
    }

    override fun openOrCreateDatabase(
        name: String,
        mode: Int,
        factory: android.database.sqlite.SQLiteDatabase.CursorFactory?,
        errorHandler: android.database.DatabaseErrorHandler?
    ): android.database.sqlite.SQLiteDatabase {
        val dbPath = getDatabasePath(name)
        dbPath.parentFile?.mkdirs()
        return android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(
            dbPath.absolutePath, factory, errorHandler
        )
    }

    override fun deleteDatabase(name: String): Boolean {
        val dbFile = getDatabasePath(name)
        return dbFile.delete()
    }

    override fun databaseList(): Array<String> {
        val dbDir = sandboxManager.getDatabasesDir(instanceId)
        return dbDir.list() ?: emptyArray()
    }

    override fun fileList(): Array<String> {
        return filesDir.list() ?: emptyArray()
    }

    override fun deleteFile(name: String): Boolean {
        return File(filesDir, name).delete()
    }

    // === Context routing overrides (Task 8) ===

    /**
     * The guest app's Application instance.
     * Must be set after bindApplication() creates the Application.
     *
     * CRITICAL: AndroidX libraries (ProcessLifecycleInitializer, WorkManager, Firebase)
     * cast the result of getApplicationContext() to Application:
     *   (Application) context.getApplicationContext()
     * If we return 'this' (a VirtualContext/ContextWrapper), they get ClassCastException.
     */
    private var guestApplication: android.app.Application? = null

    fun setGuestApplication(application: android.app.Application) {
        guestApplication = application
    }

    override fun getApplicationContext(): Context {
        // Return the guest Application if available — this is what AndroidX expects
        return guestApplication ?: super.getApplicationContext()
    }

    /**
     * When guest app requests its own package context, return self.
     * Otherwise delegate to base for real packages.
     */
    override fun createPackageContext(packageName: String, flags: Int): Context {
        if (packageName == guestPackageName) return this
        return super.createPackageContext(packageName, flags)
    }

    /**
     * Intercept startActivity — tag the intent with our instance info
     * so the ActivityManager proxy can route it correctly.
     */
    override fun startActivity(intent: Intent) {
        // Tag with virtual instance metadata for Binder proxy interception
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        super.startActivity(intent)
    }

    override fun startActivity(intent: Intent, options: android.os.Bundle?) {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        super.startActivity(intent, options)
    }

    /**
     * Tag broadcasts with instance info for the BroadcastManager proxy.
     */
    override fun sendBroadcast(intent: Intent) {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        super.sendBroadcast(intent)
    }

    override fun sendBroadcast(intent: Intent, receiverPermission: String?) {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        super.sendBroadcast(intent, receiverPermission)
    }

    /**
     * Tag service starts with instance info for ServiceLifecycleManager proxy.
     */
    override fun startService(intent: Intent): ComponentName? {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        return super.startService(intent)
    }

    override fun stopService(intent: Intent): Boolean {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        return super.stopService(intent)
    }

    // === bindService interception ===
    // Without this override, DynamiteModule-loaded GMS code (Firebase measurement,
    // analytics, etc.) calling context.bindService() bypasses our proxy layer.
    // The ServiceConnection receives an unproxied raw GMS binder, and subsequent
    // transact() calls fail because GMS sees guest pkg name but host UID.

    /**
     * Optional interceptor for wrapping binders received from service connections.
     * Set by VirtualEngine to wrap GMS binders in GmsBinderProxy.
     */
    private var binderInterceptor: ((ComponentName?, IBinder, Intent?) -> IBinder)? = null

    fun setBinderInterceptor(interceptor: (ComponentName?, IBinder, Intent?) -> IBinder) {
        binderInterceptor = interceptor
    }

    override fun bindService(intent: Intent, conn: ServiceConnection, flags: Int): Boolean {
        intent.putExtra("_nextvm_caller_instance", instanceId)
        intent.putExtra("_nextvm_caller_pkg", guestPackageName)
        val wrappedConn = wrapServiceConnection(conn, intent)
        return super.bindService(intent, wrappedConn, flags)
    }

    override fun unbindService(conn: ServiceConnection) {
        // Unbind the wrapper if we wrapped it, otherwise pass through
        val wrapper = activeConnections.remove(conn)
        super.unbindService(wrapper ?: conn)
    }

    // Map original → wrapper so unbindService can find the right one
    private val activeConnections = java.util.concurrent.ConcurrentHashMap<ServiceConnection, ServiceConnection>()

    private fun wrapServiceConnection(original: ServiceConnection, intent: Intent): ServiceConnection {
        val interceptor = binderInterceptor ?: return original
        val intentCopy = Intent(intent) // snapshot the intent for later identification
        val wrapper = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                if (service != null) {
                    try {
                        val proxied = interceptor(name, service, intentCopy)
                        original.onServiceConnected(name, proxied)
                    } catch (e: Exception) {
                        Timber.tag("VCtx").w(e, "Binder interceptor failed, delivering raw binder")
                        original.onServiceConnected(name, service)
                    }
                } else {
                    original.onServiceConnected(name, service)
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                original.onServiceDisconnected(name)
            }
        }
        activeConnections[original] = wrapper
        return wrapper
    }

    /**
     * Register broadcast receiver — tag with instance info.
     */
    override fun registerReceiver(
        receiver: BroadcastReceiver?,
        filter: IntentFilter
    ): Intent? {
        return super.registerReceiver(receiver, filter)
    }

    override fun registerReceiver(
        receiver: BroadcastReceiver?,
        filter: IntentFilter,
        flags: Int
    ): Intent? {
        return super.registerReceiver(receiver, filter, flags)
    }

    /**
     * System service requests are routed through our override above (getSystemService).
     * The SystemServiceProxyManager has already hooked the service manager
     * singletons, so most services are automatically proxied.
     */

    /**
     * Return a ClassLoader hint. If a guest-specific ClassLoader is set,
     * return it; otherwise fall back to the base ClassLoader.
     */
    private var guestClassLoader: ClassLoader? = null

    fun setGuestClassLoader(classLoader: ClassLoader) {
        guestClassLoader = classLoader
    }

    override fun getClassLoader(): ClassLoader {
        return guestClassLoader ?: super.getClassLoader()
    }

    // === Guest Resources support ===
    // When a guest app calls context.getString(R.string.foo) or context.getResources(),
    // it must resolve resource IDs from the GUEST APK, not the host's. Without this
    // override, resource IDs like 0x7f120025 are looked up in the HOST's resource table,
    // causing Resources$NotFoundException.

    private var guestResources: android.content.res.Resources? = null
    private var guestTheme: android.content.res.Resources.Theme? = null

    /**
     * Set the guest app's Resources object created from the guest APK.
     * Must be called before any code in the guest app tries to load resources.
     */
    fun setGuestResources(resources: android.content.res.Resources) {
        guestResources = resources
        // Invalidate cached theme so it gets re-created with guest resources
        guestTheme = null
    }

    override fun getResources(): android.content.res.Resources {
        return guestResources ?: super.getResources()
    }

    override fun getAssets(): android.content.res.AssetManager {
        return guestResources?.assets ?: super.getAssets()
    }

    override fun getTheme(): android.content.res.Resources.Theme {
        val res = guestResources ?: return super.getTheme()
        if (guestTheme == null) {
            guestTheme = res.newTheme().apply {
                // Apply the default system theme as a base
                try {
                    setTo(super.getTheme())
                } catch (_: Exception) { /* ignore if super theme is incompatible */ }
            }
        }
        return guestTheme!!
    }
}
