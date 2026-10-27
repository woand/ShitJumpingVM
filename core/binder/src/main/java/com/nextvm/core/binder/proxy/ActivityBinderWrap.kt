package com.nextvm.core.binder.proxy

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import android.os.IInterface
import android.os.Parcel
import android.os.UserHandle
import com.nextvm.core.model.VirtualConstants
import com.nextvm.core.model.VirtualIntentExtras
import timber.log.Timber
import java.io.File
import java.lang.reflect.Field
import java.io.FileDescriptor

/**
 * v44/v45: raw-binder interception for activity-start services.
 *
 * History: v44 wrapped only ServiceManager's "activity" entry.
 * launch63 proved no guest start ever flows over that binder (and
 * IActivityManager$Stub may not even carry startActivity codes
 * since the Android 10 split): the system records the guest's
 * GuideActivity starts under ActivityTaskManager. Guest startActivity
 * goes through IActivityTaskManager — ServiceManager name
 * "activity_task" — the standard framework path since Android 10
 * (Instrumentation.execStartActivity -> ActivityTaskManager
 * .getService()).
 *
 * v45 parameterises the wrapper per service and installs it for
 * BOTH "activity" and "activity_task":
 *  - descriptor and transaction codes come from the wrapped binder
 *    / the service's own Stub class, resolved eagerly at install
 *    and logged (a -1 code is visible, never silent);
 *  - the AIDL field order for startActivity/startActivityAsUser
 *    is identical for the two interfaces (split verbatim in
 *    Android 10), and the trace prints the parsed component, so a
 *    mis-parse would be visible on first contact;
 *  - ActivityTaskManager's singleton is inspected after wrapping:
 *    if it already cached a proxy over the raw binder, its
 *    mInstance is refilled with a proxy over the wrapped binder.
 *
 * Interception semantics are unchanged from v44: every call is
 * forwarded untouched except startActivity/startActivityAsUser,
 * whose parcels are parsed; when the intent targets a registered
 * virtual app (decided by ActivityManagerProxy
 * .rewriteGuestStartIntent), the parcel is rebuilt with the stub
 * intent and the host package as callingPackage, then forwarded.
 * Any failure degrades to forwarding the original parcel.
 *
 * Installed from NextVmApplication.onCreate (via VirtualEngine
 * .installActivityBinderWrapEarly) so it is in place before any
 * guest code can capture the binder.
 */
class ActivityBinderWrap private constructor(
    private val real: IBinder,
    private val context: Context,
    private val serviceName: String,
    private val stubClassName: String
) : IBinder {

    companion object {
        private const val TAG = "BinderWrap"

        private data class ServiceSpec(
            val name: String,
            val stubClassName: String
        )

        private val SPECS = listOf(
            ServiceSpec("activity", "android.app.IActivityManager\$Stub"),
            ServiceSpec(
                "activity_task",
                "android.app.IActivityTaskManager\$Stub"
            )
        )

        private val installedServices = mutableSetOf<String>()

        fun install(context: Context) {
            synchronized(this) {
                try {
                    val smClass = Class.forName("android.os.ServiceManager")
                    val getService = smClass.getMethod(
                        "getService", String::class.java
                    )
                    val cacheField = smClass.getDeclaredField("sCache")
                    cacheField.isAccessible = true
                    @Suppress("UNCHECKED_CAST")
                    val cache = cacheField.get(null)
                        as? MutableMap<String, IBinder>
                    if (cache == null) {
                        Timber.tag(TAG).w("ServiceManager.sCache unavailable")
                        return
                    }
                    val appCtx = context.applicationContext
                    for (spec in SPECS) {
                        if (spec.name in installedServices) continue
                        try {
                            val raw = getService.invoke(null, spec.name)
                                as? IBinder
                            if (raw == null) {
                                Timber.tag(TAG).w(
                                    "getService(%s) returned null", spec.name
                                )
                                continue
                            }
                            if (raw is ActivityBinderWrap &&
                                raw.serviceName == spec.name
                            ) {
                                installedServices += spec.name
                                continue
                            }
                            val wrap = ActivityBinderWrap(
                                raw, appCtx, spec.name, spec.stubClassName
                            )
                            cache[spec.name] = wrap
                            installedServices += spec.name
                            // Force lazy code resolution NOW so the
                            // install line witnesses the actual codes.
                            Timber.tag(TAG).i(
                                "[%s] binder wrap installed: codes %s prev=%s",
                                spec.name, wrap.codesSummary(),
                                raw.javaClass.simpleName
                            )
                            if (spec.name == "activity_task") {
                                fixupAtmSingleton(wrap)
                            }
                        } catch (t: Throwable) {
                            Timber.tag(TAG).e(
                                t, "[%s] binder wrap install failed",
                                spec.name
                            )
                        }
                    }
                } catch (t: Throwable) {
                    Timber.tag(TAG).e(t, "binder wrap install failed")
                }
            }
        }

        /**
         * ActivityTaskManager.getService() caches its proxy in a
         * static Singleton (mInstance). If that singleton was
         * already filled with a proxy over the RAW binder before
         * our wrap went in, refill it with a proxy over the
         * wrapped binder; log every outcome as witness.
         */
        private fun fixupAtmSingleton(wrap: ActivityBinderWrap) {
            try {
                val atmClass = Class.forName("android.app.ActivityTaskManager")
                val singletonField =
                    atmClass.getDeclaredField("IActivityTaskManagerSingleton")
                singletonField.isAccessible = true
                val singleton = singletonField.get(null)
                if (singleton == null) {
                    Timber.tag(TAG).i("[activity_task] atm singleton: absent")
                    return
                }
                // mInstance is declared in the android.util.Singleton
                // superclass, not in the anonymous IActivityTaskManager
                // Singleton subclass: getDeclaredField alone misses it
                // (v45 launch64 witness: NoSuchFieldException in
                // ActivityTaskManager$2). Walk the hierarchy.
                val mInstanceField = findFieldInHierarchy(
                    singleton.javaClass, "mInstance"
                ) ?: throw NoSuchFieldException(
                    "mInstance not found in hierarchy of " +
                        singleton.javaClass.name
                )
                mInstanceField.isAccessible = true
                val existing = mInstanceField.get(singleton)
                if (existing == null) {
                    Timber.tag(TAG).i(
                        "[activity_task] atm singleton: unfilled " +
                            "(first getService will see the wrap)"
                    )
                    return
                }
                val remote = findRemoteBinder(existing)
                if (remote === wrap) {
                    Timber.tag(TAG).i(
                        "[activity_task] atm singleton: already wrapped"
                    )
                    return
                }
                val stubClass =
                    Class.forName("android.app.IActivityTaskManager\$Stub")
                val asInterface = stubClass.getMethod(
                    "asInterface", IBinder::class.java
                )
                val replacement = asInterface.invoke(null, wrap)
                if (replacement == null) {
                    Timber.tag(TAG).w(
                        "[activity_task] atm singleton: asInterface(wrap) null"
                    )
                    return
                }
                mInstanceField.set(singleton, replacement)
                Timber.tag(TAG).i(
                    "[activity_task] atm singleton: REFILLED " +
                        "(was proxy over %s)",
                    remote?.javaClass?.simpleName ?: "unknown"
                )
            } catch (t: Throwable) {
                Timber.tag(TAG).w(
                    t, "[activity_task] atm singleton fixup failed"
                )
            }
        }

        /** getDeclaredField does not search superclasses; walk. */
        private fun findFieldInHierarchy(
            cls: Class<*>, name: String
        ): Field? {
            var c: Class<*>? = cls
            while (c != null) {
                try {
                    return c.getDeclaredField(name)
                } catch (e: NoSuchFieldException) {
                    c = c.superclass
                }
            }
            return null
        }

        private fun findRemoteBinder(proxy: Any): IBinder? {
            var cls: Class<*>? = proxy.javaClass
            while (cls != null) {
                try {
                    val f = cls.getDeclaredField("mRemote")
                    f.isAccessible = true
                    return f.get(proxy) as? IBinder
                } catch (e: NoSuchFieldException) {
                    cls = cls.superclass
                }
            }
            return null
        }
    }

    private val descriptor: String
        get() = real.interfaceDescriptor
            ?: if (serviceName == "activity_task") {
                "android.app.IActivityTaskManager"
            } else {
                "android.app.IActivityManager"
            }

    private val codeStartActivity: Int by lazy {
        transactionCode("TRANSACTION_startActivity")
    }
    private val codeStartActivityAsUser: Int by lazy {
        transactionCode("TRANSACTION_startActivityAsUser")
    }

    fun codesSummary(): String =
        "start=" + codeStartActivity +
            " asUser=" + codeStartActivityAsUser

    private fun transactionCode(field: String): Int = try {
        val f = Class.forName(stubClassName).getDeclaredField(field)
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
        val isStart = (codeStartActivity >= 0 &&
            code == codeStartActivity) ||
            (codeStartActivityAsUser >= 0 &&
                code == codeStartActivityAsUser)
        if (!isStart || reply == null ||
            (flags and IBinder.FLAG_ONEWAY) != 0
        ) {
            return real.transact(code, data, reply, flags)
        }
        return try {
            handleStart(
                code, data, reply, flags,
                code == codeStartActivityAsUser
            )
        } catch (t: Throwable) {
            trace("intercept failed <" + t.javaClass.simpleName + "> " +
                t.message + " — forwarding original")
            data.setDataPosition(0)
            val ok = real.transact(code, data, reply, flags)
            traceStartResult(reply, "fallback-original")
            ok
        }
    }

    /**
     * Parse a startActivity parcel (AIDL write order, identical
     * for IActivityManager and IActivityTaskManager): interface
     * token, caller binder, callingPackage, callingFeatureId,
     * intent, resolvedType, resultTo, resultWho, requestCode,
     * flags, profilerInfo, options [, userHandle]. Rebuilds and
     * forwards only when the intent is rewritten to a stub;
     * otherwise forwards the original parcel untouched.
     */
    private fun handleStart(
        code: Int,
        data: Parcel,
        reply: Parcel,
        flags: Int,
        asUser: Boolean
    ): Boolean {
        data.setDataPosition(0)
        data.enforceInterface(descriptor)
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
            val ok = real.transact(code, data, reply, flags)
            traceStartResult(reply, "null-intent")
            return ok
        }
        val proxy = ActivityManagerProxy.activeInstance
        val rewritten = proxy?.rewriteGuestStartIntent(intent)
        if (rewritten == null) {
            trace(
                "start seen, not rewritten: cmp=" + intent.component +
                    " proxyPresent=" + (proxy != null) +
                    " apps=[" + (proxy?.debugVirtualAppKeys() ?: "-") + "]"
            )
            data.setDataPosition(0)
            val ok = real.transact(code, data, reply, flags)
            traceStartResult(reply, "not-rewritten cmp=" + intent.component)
            return ok
        }
        // v78: launch101 measured origFlags=0x10000000 — NEW_TASK
        // only, no SINGLE_TOP/CLEAR_TOP — yet AMS still returned
        // START_DELIVERED_TO_TOP. Corrected hypothesis: the fold is
        // NEW_TASK task-root reuse (re-starting the running task's
        // root component with NEW_TASK delivers the intent to the
        // existing root instance instead of stacking a record). When
        // this start comes from an activity context (resultTo is the
        // caller's activity token), clearing NEW_TASK on the
        // rewritten copy makes AMS treat it as an ordinary in-task
        // start and create the record. Starts with no activity
        // context (services/receivers) keep NEW_TASK: AMS demands it
        // there and there is no source task to stack onto anyway.
        val ntCleared = if ((rewritten.flags and Intent.FLAG_ACTIVITY_NEW_TASK) != 0) {
            rewritten.flags =
                rewritten.flags and Intent.FLAG_ACTIVITY_NEW_TASK.inv()
            true
        } else {
            false
        }
        trace(
            "start REWRITTEN: " + intent.component + " -> " +
                rewritten.component + " callingPkg=" + callingPackage +
                // v77: record the guest intent's original flags before
                // the rewrite clears SINGLE_TOP/CLEAR_TOP on the copy
                // (launch100 inferred those flags from the
                // DELIVERED_TO_TOP result but never saw them directly).
                " origFlags=0x" + Integer.toHexString(intent.flags) +
                // v78: discriminator state for the NEW_TASK clearing.
                " resultTo=" + (resultTo != null) +
                " ntCleared=" + ntCleared +
                " instance=" + rewritten.getStringExtra(
                    VirtualIntentExtras.INSTANCE_ID
                ) + " slot=" + rewritten.getIntExtra(
                    VirtualIntentExtras.PROCESS_SLOT, -1
                )
        )
        val out = Parcel.obtain()
        try {
            out.writeInterfaceToken(descriptor)
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
            val ok = real.transact(code, out, reply, flags)
            traceStartResult(reply, "rewritten->" + rewritten.component)
            return ok
        } finally {
            out.recycle()
        }
    }

    /**
     * v76: read the startActivity result out of the reply parcel
     * (AIDL order: exception header, then the int result —
     * ActivityManager.START_SUCCESS=100, START_TASK_TO_FRONT=2,
     * START_DELIVERED_TO_TOP=3, negative/96..99 are failures).
     * launch99 left the guest's AppTab start unaccounted for: the
     * rewrite was witnessed but neither an AMS refusal nor a
     * delivery ever surfaced. The reply code is the one witness
     * that separates "AMS rejected it" from "AMS accepted it and
     * the delivery vanished". Best-effort: the parcel position is
     * restored and any parse failure is itself traced, never thrown.
     */
    private fun traceStartResult(reply: Parcel?, label: String) {
        if (reply == null) {
            trace("start RESULT <no reply parcel> " + label)
            return
        }
        val saved = reply.dataPosition()
        try {
            reply.setDataPosition(0)
            reply.readException()
            val result = reply.readInt()
            trace("start RESULT code=" + result + " " + label)
        } catch (t: Throwable) {
            trace(
                "start RESULT <unparseable: " +
                    t.javaClass.simpleName + "> " + label
            )
        } finally {
            try {
                reply.setDataPosition(saved)
            } catch (_: Throwable) {
            }
        }
    }

    private val traceLock = Any()

    private fun trace(msg: String) {
        Timber.tag(TAG).i("[%s] %s", serviceName, msg)
        try {
            val f = File(
                context.filesDir,
                "startactivity-trace-" +
                    android.os.Process.myPid() + ".log"
            )
            synchronized(traceLock) {
                // v76: wall-clock prefix on every trace line. launch99's
                // file had no timestamps at all, so the one witnessed
                // start could not be ordered against the logcat Risk
                // lines (same wall clock) or the delivery records.
                f.appendText(
                    "[t=" + System.currentTimeMillis() + "] " +
                        "binderwrap[" + serviceName + "]: " + msg + "\n"
                )
            }
        } catch (t: Throwable) {
            // Witness is best-effort; never break a transact over it.
        }
    }
}
