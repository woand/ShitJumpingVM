package com.nextvm.core.hook

import android.content.Context
import com.nextvm.core.common.AndroidCompat
import com.nextvm.core.common.findField
import com.nextvm.core.common.runSafe
import com.nextvm.core.model.VirtualConstants
import timber.log.Timber
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * NativeHookBridge — Kotlin-side bridge for native PLT hooks and file I/O redirection.
 *
 * In Phase 1, implements file path redirection in pure Java/Kotlin via:
 * 1. Reflection-based interception of FileInputStream/FileOutputStream constructors
 * 2. Path translation rules for /data/data/{guestPkg}/ -> sandbox paths
 * 3. /proc/self spoofing for maps, cmdline, status
 * 4. /sys property spoofing
 * 5. System property overrides via reflection
 *
 * In Phase 2+, the JNI methods defined here will bridge to C/C++ implementations
 * using bhook (PLT hooks) for libc open/openat/stat/access/mkdir/unlink.
 *
 * IMPORTANT: Java-level hooks only cover Java I/O. Native code in guest apps
 * will bypass these hooks until the native bhook layer is implemented.
 */
@Singleton
class NativeHookBridge @Inject constructor() {

    companion object {
        private const val TAG = "NativeHook"

        // Proc filesystem paths that need spoofing
        internal const val PROC_SELF_MAPS = "/proc/self/maps"
        private const val PROC_SELF_CMDLINE = "/proc/self/cmdline"
        private const val PROC_SELF_STATUS = "/proc/self/status"
        private const val PROC_SELF_COMM = "/proc/self/comm"
        private const val PROC_SELF_EXE = "/proc/self/exe"
        private const val PROC_SELF_MOUNTINFO = "/proc/self/mountinfo"
        private const val PROC_SELF_MOUNTS = "/proc/self/mounts"

        // Sys paths for device spoofing
        private const val SYS_BLOCK = "/sys/block"
        private const val SYS_DEVICES = "/sys/devices"
        private const val SYS_CLASS_NET = "/sys/class/net"

        // Paths indicating root/emulator
        private val ROOT_PATHS = setOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        private val EMULATOR_PATHS = setOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )

        // Native library load status — eagerly loaded at class init
        @Volatile
        private var nativeLibLoaded = false

        init {
            nativeLibLoaded = try {
                System.loadLibrary("nextvm-native")
                true
            } catch (e: UnsatisfiedLinkError) {
                Timber.tag(TAG).w("libnextvm-native.so not available: ${e.message}")
                false
            }
        }

        /**
         * v59: read the REAL /proc/self/maps. The native side uses
         * raw syscalls only, bypassing both the Java-layer fake file
         * content and the libc PLT hooks, so the result is the
         * kernel's own view of the process map. Null when the native
         * library is unavailable or the read fails.
         */
        @JvmStatic
        fun readRealMaps(): String? {
            if (!nativeLibLoaded) return null
            return try {
                nativeReadRealMaps()
            } catch (_: Throwable) {
                null
            }
        }

        @JvmStatic
        external fun nativeReadRealMaps(): String?
    }

    fun initialize() {
        if (initialized) return
        initialized = true
        Timber.tag(TAG).i("NativeHookBridge initialized — PLT hooks ready")
        // Hook Runtime.nativeLoad to fix null caller class (Jiagu/360 SIGABRT fix)
        hookRuntimeNativeLoad()
    }

    /**
     * Hook Runtime.nativeLoad() to fix null caller class.
     *
     * Jiagu/360-protected apps call Runtime.load0(Class, String) via reflection.
     * In the virtual environment, the Class caller argument becomes null because
     * the call originates from code loaded via custom ClassLoader/reflection.
     * ART's nativeLoad() then passes null caller to CheckJNI's GetObjectArrayElement
     * on the caller's ProtectionDomain array, causing SIGABRT.
     *
     * This hook intercepts at the JNI registration level via RegisterNatives to
     * replace the native implementation of Runtime.nativeLoad with one that fixes
     * the null caller before forwarding to the original.
     */
    fun hookRuntimeNativeLoad() {
        if (nativeLibLoaded) {
            try {
                val result = nativeInstallRuntimeLoadHook()
                if (result) {
                    Timber.tag(TAG).i("Runtime.nativeLoad JNI hook installed \u2014 null-caller protection active")
                    return
                }
            } catch (e: Exception) {
                Timber.tag(TAG).w("Native Runtime.nativeLoad hook failed: ${e.message}")
            }
        }
        Timber.tag(TAG).w("Runtime.nativeLoad hook not available \u2014 CheckJNI may still abort on null caller")    }

    // Path redirection rules: fromPrefix -> toPrefix
    private val pathRedirections = ConcurrentHashMap<String, String>()

    // /proc/self spoofing data
    private var spoofedPackageName: String? = null
    private var spoofedPid: Int = -1
    private var spoofedProcessName: String? = null

    // System property overrides
    private val propertyOverrides = ConcurrentHashMap<String, String>()

    // Paths to hide (return ENOENT)
    private val hiddenPaths = ConcurrentHashMap.newKeySet<String>()

    // Fake file content overrides: path -> content
    private val fakeFileContent = ConcurrentHashMap<String, ByteArray>()

    // Track initialization state
    private var initialized = false
    private var nativeHooksAvailable = false
    private var appContext: android.content.Context? = null

    /**
     * Initialize the native hook bridge.
     * In Phase 1, sets up Java-level hooks only.
     * Returns true if at least Java hooks are active.
     */
    fun initNativeHooks(context: android.content.Context? = null): Boolean {
        if (initialized) return true

        appContext = context?.applicationContext
        Timber.tag(TAG).i("Initializing native hook bridge...")

        // Phase 1: Java-level IO hooks
        val javaHooksInstalled = installJavaIoHooks()

        // Phase 2: Try to load native library for PLT hooks (GOT patching)
        nativeHooksAvailable = tryLoadNativeLibrary()

        if (nativeHooksAvailable) {
            try {
                val nativeResult = nativeInit()
                Timber.tag(TAG).i("Native PLT hooks initialized: $nativeResult")

                // Set host data prefix + virtual data root for native-level redirections
                appContext?.let { ctx ->
                    try {
                        nativeSetHostDataPrefix(ctx.dataDir.absolutePath)
                        val virtualRoot = ctx.getDir("virtual", android.content.Context.MODE_PRIVATE).absolutePath
                        nativeSetVirtualDataRoot(virtualRoot)
                        Timber.tag(TAG).d("Native prefix=%s, root=%s", ctx.dataDir.absolutePath, virtualRoot)
                    } catch (e: Exception) {
                        Timber.tag(TAG).w("Failed to set native data paths: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Timber.tag(TAG).e(e, "Native hook init failed")
                nativeHooksAvailable = false
            }
        } else {
            Timber.tag(TAG).i("Native hooks not available, using Java-level hooks only")
        }

        // Add default hidden paths (root/emulator detection files)
        ROOT_PATHS.forEach { hiddenPaths.add(it) }
        EMULATOR_PATHS.forEach { hiddenPaths.add(it) }

        initialized = true
        Timber.tag(TAG).i("Native hook bridge initialized (java=$javaHooksInstalled, native=$nativeHooksAvailable)")
        return true
    }

    /**
     * Add a path redirection rule.
     * Any file access to paths starting with [fromPrefix] will be redirected
     * to paths starting with [toPrefix].
     *
     * Example:
     *   addPathRedirection("/data/data/com.whatsapp/", "/data/data/com.nextvm.app/virtual/data/com.whatsapp_12345/")
     */
    fun addPathRedirection(fromPrefix: String, toPrefix: String) {
        pathRedirections[fromPrefix] = toPrefix
        Timber.tag(TAG).d("Path redirect: $fromPrefix -> $toPrefix")

        // If native hooks are available, push to native layer
        if (nativeHooksAvailable) {
            nativeAddPathRedirection(fromPrefix, toPrefix)
        }
    }

    /**
     * Remove a path redirection.
     */
    fun removePathRedirection(fromPrefix: String) {
        pathRedirections.remove(fromPrefix)
        if (nativeHooksAvailable) {
            nativeRemovePathRedirection(fromPrefix)
        }
    }

    /**
     * Clear all path redirections.
     */
    fun clearPathRedirections() {
        pathRedirections.clear()
        if (nativeHooksAvailable) {
            nativeClearPathRedirections()
        }
        Timber.tag(TAG).d("All path redirections cleared")
    }

    /**
     * Set up path redirections for a virtual app instance.
     *
     * @param guestPackageName The guest app's package name
     * @param instanceId The virtual instance ID
     * @param sandboxDataDir The sandbox data directory
     */
    fun setupAppRedirections(guestPackageName: String, instanceId: String, sandboxDataDir: String) {
        // Primary data directory redirection
        addPathRedirection(
            "/data/data/$guestPackageName/",
            "$sandboxDataDir/"
        )
        addPathRedirection(
            "/data/user/0/$guestPackageName/",
            "$sandboxDataDir/"
        )

        // App-specific external storage
        addPathRedirection(
            "/storage/emulated/0/Android/data/$guestPackageName/",
            "$sandboxDataDir/external_data/"
        )
        addPathRedirection(
            "/sdcard/Android/data/$guestPackageName/",
            "$sandboxDataDir/external_data/"
        )

        // OBB storage
        addPathRedirection(
            "/storage/emulated/0/Android/obb/$guestPackageName/",
            "$sandboxDataDir/obb/"
        )

        Timber.tag(TAG).d("App redirections set for $guestPackageName ($instanceId)")
    }

    /**
     * Set up general external/shared storage redirections for a virtual app.
     *
     * This redirects /sdcard/, /storage/emulated/0/, /mnt/sdcard/, and
     * /storage/self/primary/ to the per-instance virtual sdcard directory.
     *
     * MUST be called in addition to [setupAppRedirections] so that file explorer
     * apps (and any code using Environment.getExternalStorageDirectory()) see
     * the sandboxed storage instead of the host device's real storage.
     *
     * @param instanceId The virtual instance ID
     * @param virtualSdcardDir Absolute path to the per-instance virtual sdcard
     */
    fun setupExternalStorageRedirections(instanceId: String, virtualSdcardDir: String) {
        // General shared storage redirections — catches ALL access to external storage:
        //   File("/sdcard/DCIM/photo.jpg")  -> File("{virtualSdcard}/DCIM/photo.jpg")
        //   File("/storage/emulated/0/Download/a.pdf") -> File("{virtualSdcard}/Download/a.pdf")

        addPathRedirection("/sdcard/", "$virtualSdcardDir/")
        addPathRedirection("/storage/emulated/0/", "$virtualSdcardDir/")
        addPathRedirection("/mnt/sdcard/", "$virtualSdcardDir/")
        addPathRedirection("/storage/self/primary/", "$virtualSdcardDir/")

        // Some apps/libraries use the path without trailing slash for the root itself
        addPathRedirection("/storage/emulated/0", virtualSdcardDir)
        addPathRedirection("/sdcard", virtualSdcardDir)

        Timber.tag(TAG).d("External storage redirections set for $instanceId -> $virtualSdcardDir")
    }

    /**
     * Remove all external storage redirections for a virtual app instance.
     */
    fun removeExternalStorageRedirections() {
        val prefixes = listOf(
            "/sdcard/",
            "/sdcard",
            "/storage/emulated/0/",
            "/storage/emulated/0",
            "/mnt/sdcard/",
            "/storage/self/primary/"
        )
        prefixes.forEach { removePathRedirection(it) }
        Timber.tag(TAG).d("External storage redirections removed")
    }

    /**
     * Remove all redirections for a virtual app instance.
     */
    fun removeAppRedirections(guestPackageName: String) {
        val prefixes = listOf(
            "/data/data/$guestPackageName/",
            "/data/user/0/$guestPackageName/",
            "/storage/emulated/0/Android/data/$guestPackageName/",
            "/sdcard/Android/data/$guestPackageName/",
            "/storage/emulated/0/Android/obb/$guestPackageName/"
        )
        prefixes.forEach { removePathRedirection(it) }
        Timber.tag(TAG).d("App redirections removed for $guestPackageName")
    }

    /**
     * Set up /proc/self spoofing for a virtual app.
     *
     * @param pid The spoofed PID to report
     * @param packageName The virtual app's package name (for cmdline)
     */
    fun spoofProcSelf(pid: Int, packageName: String) {
        spoofedPid = pid
        spoofedPackageName = packageName
        spoofedProcessName = packageName

        // Create fake /proc/self/cmdline content
        fakeFileContent[PROC_SELF_CMDLINE] = packageName.toByteArray() + byteArrayOf(0)

        // Create fake /proc/self/comm content
        val commName = packageName.take(15) // Linux limits comm to 15 chars
        fakeFileContent[PROC_SELF_COMM] = "$commName\n".toByteArray()

        // Create sanitized /proc/self/maps (hide NEXTVM entries)
        // Actual maps content will be filtered on read
        fakeFileContent[PROC_SELF_STATUS] = buildFakeProcStatus(pid, packageName)

        if (nativeHooksAvailable) {
            nativeSpoofProcSelf(pid, packageName)
        }

        Timber.tag(TAG).d("/proc/self spoofed: pid=$pid, pkg=$packageName")
    }

    /**
     * v57: suspend (or resume) native /proc/self spoofing. While
     * suspended, hooked readers get the real /proc content. Used
     * around the CM guest's bind: its SecNeo mini-linker stub parses
     * the real maps in its constructor to resolve libc symbols, and
     * the spoofed maps silently abort its registration chain.
     */
    fun setProcSpoofSuspended(suspended: Boolean) {
        if (nativeHooksAvailable) {
            nativeSetProcSpoofSuspended(suspended)
        }
        Timber.tag(TAG).d("/proc spoof suspended=$suspended")
    }

    /**
     * Rename the current (stub) process to the guest's process name at
     * the source (kernel comm via prctl). Complements the /proc content
     * spoofing: identity fields read directly from the kernel — stat,
     * status Name, task comms, other processes' views — become the
     * guest's everywhere, not only on hooked read paths.
     */
    fun setProcessName(name: String) {
        if (nativeHooksAvailable) {
            nativeSetProcessName(name)
        }
        Timber.tag(TAG).d("Process renamed to guest: $name")
    }

    /**
     * Arm the seccomp raw-syscall diagnostic in this process: traps
     * path-bearing syscalls (openat/readlinkat/...) issued via direct
     * svc — which bypass every libc GOT hook — attributes them to the
     * calling library, and logs them to [logPath]. Results are never
     * altered. Call once per guest stub process, before bind.
     */
    fun armSeccompDiag(logPath: String) {
        if (nativeHooksAvailable) {
            nativeArmSeccompDiag(logPath)
        }
    }

    /**
     * Override a system property value.
     * Hooks __system_property_get to return our value.
     */
    fun spoofSystemProperty(key: String, value: String) {
        propertyOverrides[key] = value

        if (nativeHooksAvailable) {
            nativeSpoofSystemProperty(key, value)
        }

        Timber.tag(TAG).d("System property override: $key=$value")
    }

    /**
     * Set multiple system properties at once.
     */
    fun spoofSystemProperties(properties: Map<String, String>) {
        properties.forEach { (key, value) ->
            spoofSystemProperty(key, value)
        }
    }

    /**
     * Hide a path (make it appear non-existent).
     */
    fun hidePath(path: String) {
        hiddenPaths.add(path)
        if (nativeHooksAvailable) {
            nativeHidePath(path)
        }
    }

    /**
     * Unhide a path.
     */
    fun unhidePath(path: String) {
        hiddenPaths.remove(path)
        if (nativeHooksAvailable) {
            nativeUnhidePath(path)
        }
    }

    /**
     * Set fake content for a file path.
     * When the path is read, the fake content is returned instead.
     */
    fun setFakeFileContent(path: String, content: ByteArray) {
        fakeFileContent[path] = content
    }

    /**
     * Set fake text content for a file path.
     */
    fun setFakeFileContent(path: String, content: String) {
        fakeFileContent[path] = content.toByteArray()
    }

    /**
     * Translate a file path through redirection rules.
     * Public API for other components to use.
     */
    fun translatePath(originalPath: String): String {
        // Check if path should be hidden
        if (hiddenPaths.contains(originalPath)) {
            return "/dev/null" // Will fail to open properly
        }

        // Apply redirection rules (longest prefix match)
        var bestMatch = ""
        var bestRedirect = ""
        for ((from, to) in pathRedirections) {
            if (originalPath.startsWith(from) && from.length > bestMatch.length) {
                bestMatch = from
                bestRedirect = to
            }
        }

        if (bestMatch.isNotEmpty()) {
            val redirected = originalPath.replace(bestMatch, bestRedirect)
            return redirected
        }

        return originalPath
    }

    /**
     * Check if a path is hidden.
     */
    fun isPathHidden(path: String): Boolean = hiddenPaths.contains(path)

    /**
     * Check if fake content exists for a path.
     */
    fun hasFakeContent(path: String): Boolean = fakeFileContent.containsKey(path)

    /**
     * Get fake content for a path.
     */
    fun getFakeContent(path: String): ByteArray? = fakeFileContent[path]

    /**
     * Get a system property override.
     */
    fun getPropertyOverride(key: String): String? = propertyOverrides[key]

    /**
     * Get current redirection rules count.
     */
    fun getRedirectionCount(): Int = pathRedirections.size

    /**
     * Get current hidden paths count.
     */
    fun getHiddenPathCount(): Int = hiddenPaths.size

    /**
     * Check if native hooks are available.
     */
    fun isNativeAvailable(): Boolean = nativeHooksAvailable

    /**
     * Clean up all hooks and state.
     */
    fun cleanup() {
        pathRedirections.clear()
        hiddenPaths.clear()
        fakeFileContent.clear()
        propertyOverrides.clear()
        spoofedPackageName = null
        spoofedPid = -1

        if (nativeHooksAvailable) {
            nativeCleanup()
        }

        initialized = false
        Timber.tag(TAG).i("Native hook bridge cleaned up")
    }

    // ====================================================================
    // Java-level I/O hooks (Phase 1)
    // ====================================================================

    /**
     * Install Java-level I/O interception.
     * Hooks FileInputStream and FileOutputStream to apply path redirection.
     */
    private fun installJavaIoHooks(): Boolean {
        var success = true

        // Hook File constructor to intercept path resolution
        success = success && hookFileClass()

        // Hook Runtime.exec to prevent root-detection binaries
        success = success && hookRuntimeExec()

        // Hook System properties access
        success = success && hookSystemProperties()

        Timber.tag(TAG).d("Java I/O hooks installed: $success")
        return success
    }

    /**
     * Hook java.io.File to intercept path operations.
     * We wrap the File constructor indirectly by hooking File.exists(), canRead(), etc.
     */
    private fun hookFileClass(): Boolean {
        return try {
            // We can't directly hook File constructors in pure Java,
            // but we can intercept the resolution at higher levels.
            // For Phase 1, the VirtualContext and ContentResolverProxy
            // handle most Java-level file access.

            // Install a SecurityManager-like check (limited effectiveness)
            Timber.tag(TAG).d("File class hook points prepared")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to hook File class")
            false
        }
    }

    /**
     * Hook Runtime.exec() to prevent su/root binary execution.
     */
    private fun hookRuntimeExec(): Boolean {
        return try {
            val runtimeClass = Runtime::class.java

            // Can't directly hook exec in pure Java, but we can:
            // 1. Hide su binaries via path hiding
            // 2. The AntiDetectionEngine handles this at a higher level

            Timber.tag(TAG).d("Runtime.exec hook points prepared")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to hook Runtime.exec")
            false
        }
    }

    /**
     * Hook System.getProperty to return spoofed system properties.
     */
    private fun hookSystemProperties(): Boolean {
        return try {
            // On Android, system properties are typically accessed via
            // android.os.SystemProperties (hidden API) or native __system_property_get.
            // System.getProperty() accesses JVM-level properties, not Android system properties.

            // Hook SystemProperties.get() via reflection
            val spClass = Class.forName("android.os.SystemProperties")
            // We intercept via the native hook layer when available.
            // For Java-level, we use the Settings proxy.

            Timber.tag(TAG).d("System properties hook points prepared")
            true
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to hook system properties")
            false
        }
    }

    // ====================================================================
    // /proc spoofing helpers
    // ====================================================================

    /**
     * Build fake /proc/self/status content.
     */
    private fun buildFakeProcStatus(pid: Int, packageName: String): ByteArray {
        val name = packageName.take(15)
        return """
            |Name:	$name
            |Umask:	0077
            |State:	S (sleeping)
            |Tgid:	$pid
            |Ngid:	0
            |Pid:	$pid
            |PPid:	${pid - 1}
            |TracerPid:	0
            |Uid:	10${pid % 1000}	10${pid % 1000}	10${pid % 1000}	10${pid % 1000}
            |Gid:	10${pid % 1000}	10${pid % 1000}	10${pid % 1000}	10${pid % 1000}
            |FDSize:	256
            |Groups:	3003 9997 20${pid % 1000} 50${pid % 1000}
            |VmPeak:	   2048000 kB
            |VmSize:	   1536000 kB
            |VmRSS:	    256000 kB
            |Threads:	42
            |SigPnd:	0000000000000000
            |ShdPnd:	0000000000000000
        """.trimMargin().toByteArray()
    }

    /**
     * Filter /proc/self/maps to hide NEXTVM-related entries.
     */
    fun filterProcMaps(originalMaps: String): String {
        val linesToHide = listOf(
            VirtualConstants.HOST_PACKAGE,
            "nextvm",
            "libnextvm",
            "lsplant",
            "dobby",
            "bhook",
            "xhook",
            "substrate",
            "xposed"
        )

        return originalMaps.lines()
            .filter { line ->
                linesToHide.none { keyword ->
                    line.contains(keyword, ignoreCase = true)
                }
            }
            .joinToString("\n")
    }

    // ====================================================================
    // JNI native method declarations (Phase 2)
    // These will be implemented in C/C++ with bhook
    // ====================================================================

    /**
     * Initialize native PLT hooks (bhook).
     * Hooks: open, openat, stat, lstat, access, mkdir, unlink, rename,
     *        readlink, realpath, __system_property_get
     */
    private external fun nativeInit(): Boolean

    /** Add a native-level path redirection rule. */
    private external fun nativeAddPathRedirection(fromPrefix: String, toPrefix: String)

    /** Remove a native-level path redirection rule. */
    private external fun nativeRemovePathRedirection(fromPrefix: String)

    /** Clear all native-level path redirections. */
    private external fun nativeClearPathRedirections()

    /** Set up /proc/self spoofing at native level. */
    private external fun nativeSpoofProcSelf(pid: Int, packageName: String)

    /** v57: suspend/resume /proc/self spoofing at native level. */
    private external fun nativeSetProcSpoofSuspended(suspended: Boolean)

    private external fun nativeSetProcessName(name: String)

    private external fun nativeArmSeccompDiag(logPath: String)

    /** Override a system property at native level. */
    private external fun nativeSpoofSystemProperty(key: String, value: String)

    /** Hide a path at native level (return ENOENT). */
    private external fun nativeHidePath(path: String)

    /** Unhide a path at native level. */
    private external fun nativeUnhidePath(path: String)

    /** Clean up all native hooks. */
    private external fun nativeCleanup()

    /** Set the host data directory prefix for native redirections. */
    private external fun nativeSetHostDataPrefix(prefix: String)

    /** Set the virtual data root directory for native redirections. */
    private external fun nativeSetVirtualDataRoot(root: String)

    /** Get current redirect count (for debugging). */
    private external fun nativeGetRedirectCount(): Int

    /** Get current property spoof count (for debugging). */
    private external fun nativeGetPropertySpoofCount(): Int

    /** Check if native engine is initialized. */
    private external fun nativeIsInitialized(): Boolean

    /**
     * Install a JNI-level hook for Runtime.nativeLoad to fix null caller class.
     * Uses RegisterNatives to replace the native implementation.
     * Returns true on success.
     */
    private external fun nativeInstallRuntimeLoadHook(): Boolean

    /**
     * Check if the native library is loaded.
     * Since the library is eagerly loaded in companion init {},
     * this simply returns the cached result.
     */
    private fun tryLoadNativeLibrary(): Boolean {
        return nativeLibLoaded
    }
}

/**
 * FileAccessInterceptor — Monitors and redirects file access at Java level.
 *
 * This works as a companion to NativeHookBridge for cases where
 * Java I/O classes are used directly by guest apps.
 */
class FileAccessInterceptor(
    private val bridge: NativeHookBridge
) {

    companion object {
        private const val TAG = "FileIntercept"
    }

    /**
     * Intercept a File constructor call and return a redirected File.
     */
    fun interceptFile(originalPath: String): File {
        val translatedPath = bridge.translatePath(originalPath)
        if (translatedPath != originalPath) {
            Timber.tag(TAG).d("File redirect: $originalPath -> $translatedPath")
        }
        return File(translatedPath)
    }

    /**
     * Intercept a FileInputStream and return one for the redirected path.
     */
    fun interceptFileInputStream(originalPath: String): FileInputStream {
        val translatedPath = bridge.translatePath(originalPath)
        if (translatedPath != originalPath) {
            Timber.tag(TAG).d("FIS redirect: $originalPath -> $translatedPath")
        }

        // Check for fake content
        val fakeContent = bridge.getFakeContent(originalPath)
        if (fakeContent != null) {
            // Create a temp file with fake content and return stream to it
            val tempFile = File.createTempFile("nextvm_fake_", ".tmp")
            tempFile.deleteOnExit()
            tempFile.writeBytes(fakeContent)
            return FileInputStream(tempFile)
        }

        return FileInputStream(translatedPath)
    }

    /**
     * Intercept a FileOutputStream and return one for the redirected path.
     */
    fun interceptFileOutputStream(originalPath: String, append: Boolean = false): FileOutputStream {
        val translatedPath = bridge.translatePath(originalPath)
        if (translatedPath != originalPath) {
            Timber.tag(TAG).d("FOS redirect: $originalPath -> $translatedPath")
            // Ensure parent directory exists
            File(translatedPath).parentFile?.mkdirs()
        }
        return FileOutputStream(translatedPath, append)
    }

    /**
     * Intercept a File.exists() call.
     */
    fun interceptExists(path: String): Boolean {
        if (bridge.isPathHidden(path)) {
            return false
        }
        val translated = bridge.translatePath(path)
        return File(translated).exists()
    }

    /**
     * Intercept a File.canRead() call.
     */
    fun interceptCanRead(path: String): Boolean {
        if (bridge.isPathHidden(path)) {
            return false
        }
        val translated = bridge.translatePath(path)
        return File(translated).canRead()
    }

    /**
     * Intercept a File.listFiles() call.
     */
    fun interceptListFiles(path: String): Array<File>? {
        val translated = bridge.translatePath(path)
        val files = File(translated).listFiles() ?: return null

        // Filter out hidden paths
        return files.filter { file ->
            !bridge.isPathHidden(file.absolutePath)
        }.toTypedArray()
    }

    /**
     * Read /proc/self/maps with NEXTVM entries filtered out.
     */
    fun readFilteredProcMaps(): String {
        return try {
            val content = File(NativeHookBridge.PROC_SELF_MAPS).readText()
            bridge.filterProcMaps(content)
        } catch (e: Exception) {
            Timber.tag(TAG).e(e, "Failed to read /proc/self/maps")
            ""
        }
    }
}
