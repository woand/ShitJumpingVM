package com.nextvm.core.binder.proxy

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import android.os.IInterface
import android.os.Parcel
import android.os.UserHandle
import com.nextvm.core.model.VirtualConstants
import timber.log.Timber
import java.io.File
import java.io.FileDescriptor

/**
 * v44: raw-binder interception for the "activity" service.
 *
 * launch61 (witness counters in ActivityManagerProxy) proved that
 * guest code in a guest process makes ZERO AMS calls through
 * ActivityManager.getService() — the singleton the engine replaces —
 * while its startActivity calls still reach the real AMS with raw
 * component names and die on Permission Denial. The guest (via its
 * shell / anti-hijack layer) resolves AMS through the raw binder:
 * ServiceManager.getService("activity") -> IActivityManager.Stub
 * .asInterface(binder), with the binder captured from
 * ServiceManager's cache.
 *
 * This wrapper replaces the "activity" entry in ServiceManager
 * .sCache with a delegating IBinder. Every call is forwarded
 * untouched except startActivity / startActivityAsUser, whose
 * parcels are parsed; when the intent targets a registered virtual
 * app (decided by ActivityManagerProxy.rewriteGuestStartIntent,
 * the same logic as the singleton proxy's handleStartActivity),
 * the parcel is rebuilt with the stub intent and the host package
 * as callingPackage, then forwarded — the system AMS launches the
 * stub activity and the engine's normal stub machinery takes over.
 *
 * Installed from NextVmApplication.onCreate (via VirtualEngine
 * .installActivityBinderWrapEarly) so it is in place before any
 * guest code can capture the binder. Any failure degrades to
 * forwarding the original parcel untouched.
 */
class ActivityBinderWrap private constructor(
    private val real: IBinder,
    private val context: Context
) : IBinder {

    companion object {
        private const val TAG = "BinderWrap"
        private const val DESCRIPTOR = "android.app.IActivityManager"
        private const val SERVICE = "activity"

        @Volatile
        private var installed = false

        fun install(context: Context) {
            if (installed) return
            synchronized(this) {
                if (installed) return
                try {
                    val smClass = Class.forName("android.os.ServiceManager")
                    val getService = smClass.getMethod(
                        "getService", String::class.java
                    )
                    val raw = getService.invoke(null, SERVICE) as? IBinder
                    if (raw == null) {
                        Timber.tag(TAG).w("getService(activity) returned null")
                        return
                    }
                    if (raw is ActivityBinderWrap) {
                        installed = true
                        return
                    }
                    val cacheField = smClass.getDeclaredField("sCache")
                    cacheField.isAccessible = true
                    @Suppress("UNCHECKED_CAST")
                    val cache = cacheField.get(null)
                        as? MutableMap<String, IBinder>
                    if (cache == null) {
                        Timber.tag(TAG).w("ServiceManager.sCache unavailable")
                        return
                    }
                    cache[SERVICE] = ActivityBinderWrap(
                        raw, context.applicationContext
                    )
                    installed = true
                    Timber.tag(TAG).i("activity binder wrap installed")
                } catch (t: Throwable) {
                    Timber.tag(TAG).e(t, "activity binder wrap install failed")
                }
            }
        }
    }

    private val codeStartActivity: Int by lazy {
        transactionCode("TRANSACTION_startActivity")
    }
    private val codeStartActivityAsUser: Int by lazy {
        transactionCode("TRANSACTION_startActivityAsUser")
    }

    private fun transactionCode(field: String): Int = try {
        val f = Class.forName("android.app.IActivityManager\$Stub")
            .getDeclaredField(field)
        f.isAccessible = true
        f.getInt(null)
    } catch (t: Throwable) {
        -1
    }

    // android.app.ProfilerInfo is a hidden class (absent from the
    // SDK stubs), so its CREATOR is fetched reflectively. Used only
    // to step over / copy the profilerInfo field of the parcel.
    private val profilerInfoCreator: android.os.Parcelable.Creator<*>? =
        try {
            Class.forName("android.app.ProfilerInfo")
                .getField("CREATOR")
                .get(null) as? android.os.Parcelable.Creator<*>
        } catch (t: Throwable) {
            null
        }

    // ---- IBinder delegation ----

    override fun getInterfaceDescriptor(): String? =
        real.interfaceDescriptor

    override fun pingBinder(): Boolean = real.pingBinder()

    override fun isBinderAlive(): Boolean = real.isBinderAlive

    override fun queryLocalInterface(descriptor: String): IInterface? =
        real.queryLocalInterface(descriptor)

    override fun dump(fd: FileDescriptor, args: Array<out String>?) {
        @Suppress("UNCHECKED_CAST")
        real.dump(fd, args as Array<String>?)
    }

    override fun dumpAsync(fd: FileDescriptor, args: Array<out String>?) {
        @Suppress("UNCHECKED_CAST")
        real.dumpAsync(fd, args as Array<String>?)
    }

    override fun linkToDeath(recipient: IBinder.DeathRecipient, flags: Int) {
        real.linkToDeath(recipient, flags)
    }

    override fun unlinkToDeath(
        recipient: IBinder.DeathRecipient,
        flags: Int
    ): Boolean = real.unlinkToDeath(recipient, flags)

    override fun transact(
        code: Int,
        data: Parcel,
        reply: Parcel?,
        flags: Int
    ): Boolean {
        val isStart = code == codeStartActivity ||
            code == codeStartActivityAsUser
        if (!isStart || reply == null ||
            (flags and IBinder.FLAG_ONEWAY) != 0
        ) {
            return real.transact(code, data, reply, flags)
        }
        return try {
            handleStart(code, data, reply, flags,
                code == codeStartActivityAsUser)
        } catch (t: Throwable) {
            trace("intercept failed <" + t.javaClass.simpleName + "> " +
                t.message + " — forwarding original")
            data.setDataPosition(0)
            real.transact(code, data, reply, flags)
        }
    }

    /**
     * Parse a startActivity parcel (AIDL write order, stable since
     * Android 10): interface token, caller binder, callingPackage,
     * callingFeatureId, intent, resolvedType, resultTo, resultWho,
     * requestCode, flags, profilerInfo, options [, userHandle].
     * Rebuilds and forwards only when the intent is rewritten to a
     * stub; otherwise forwards the original parcel untouched.
     */
    private fun handleStart(
        code: Int,
        data: Parcel,
        reply: Parcel,
        flags: Int,
        asUser: Boolean
    ): Boolean {
        data.setDataPosition(0)
        data.enforceInterface(DESCRIPTOR)
        val caller = data.readStrongBinder()
        val callingPackage = data.readString()
        val callingFeatureId = data.readString()
        val intent = data.readTypedObject(Intent.CREATOR)
        val resolvedType = data.readString()
        val resultTo = data.readStrongBinder()
        val resultWho = data.readString()
        val requestCode = data.readInt()
        val startFlags = data.readInt()
        val profilerCreator = profilerInfoCreator
            ?: throw IllegalStateException("ProfilerInfo CREATOR unavailable")
        val profilerInfo: Any? = data.readTypedObject(profilerCreator)
        val options = data.readTypedObject(Bundle.CREATOR)
        val userHandle = if (asUser) {
            data.readTypedObject(UserHandle.CREATOR)
        } else {
            null
        }

        if (intent == null) {
            data.setDataPosition(0)
            return real.transact(code, data, reply, flags)
        }
        val proxy = ActivityManagerProxy.activeInstance
        val rewritten = proxy?.rewriteGuestStartIntent(intent)
        if (rewritten == null) {
            trace("start seen, not rewritten: cmp=" + intent.component +
                " proxyPresent=" + (proxy != null))
            data.setDataPosition(0)
            return real.transact(code, data, reply, flags)
        }
        trace("start REWRITTEN: " + intent.component + " -> " +
            rewritten.component + " callingPkg=" + callingPackage)
        val out = Parcel.obtain()
        try {
            out.writeInterfaceToken(DESCRIPTOR)
            out.writeStrongBinder(caller)
            out.writeString(VirtualConstants.HOST_PACKAGE)
            out.writeString(callingFeatureId)
            out.writeTypedObject(rewritten, 0)
            out.writeString(resolvedType)
            out.writeStrongBinder(resultTo)
            out.writeString(resultWho)
            out.writeInt(requestCode)
            out.writeInt(startFlags)
            out.writeTypedObject(profilerInfo as? android.os.Parcelable, 0)
            out.writeTypedObject(options, 0)
            if (asUser) out.writeTypedObject(userHandle, 0)
            return real.transact(code, out, reply, flags)
        } finally {
            out.recycle()
        }
    }

    private val traceLock = Any()

    private fun trace(msg: String) {
        Timber.tag(TAG).i(msg)
        try {
            val f = File(
                context.filesDir,
                "startactivity-trace-" +
                    android.os.Process.myPid() + ".log"
            )
            synchronized(traceLock) {
                f.appendText("binderwrap: " + msg + "\n")
            }
        } catch (t: Throwable) {
            // Witness is best-effort; never break a transact over it.
        }
    }
}
