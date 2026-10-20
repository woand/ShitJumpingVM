package com.nextvm.core.virtualization.lifecycle

import java.io.File
import java.lang.reflect.Field
import java.util.concurrent.atomic.AtomicBoolean

/**
 * v38: read-only reflective state probe for the Unicom splash stall.
 *
 * Static reading of the shell-restored dex (v37 dumps) mapped the
 * whole WelcomeClient startup chain and showed the two network
 * requests are failure-tolerant (every error consumer still turns
 * its gate key), while runtime evidence says neither request ever
 * executed in the sandbox (no loopj threads ever existed). The stall
 * therefore sits in the short segment onResume -> startUp ->
 * checkYinsiDialog -> init, whose branch inputs are runtime state:
 * three SharedPreference booleans, Activity.isTaskRoot()/intent
 * shape, SoulPermission.getTopActivity(), and whether the ad
 * manager singleton was ever created. None of that is visible
 * statically, so this probe samples it reflectively, in-process,
 * at +2/+7/+15/+30s after bind.
 *
 * Strictly read-only: it never writes a guest field, never calls a
 * guest method with side effects beyond the getters the guest code
 * itself calls on this path (getTopActivity, isTaskRoot). Every step
 * is individually try/catch'd and failures are logged as data.
 * Unicom only, once per process. Output: stateprobe-<pid>.log next
 * to the other guest diagnostics.
 *
 * v42: (1) the thread census no longer calls
 * Thread.getAllStackTraces() — that suspends every thread, and in
 * launch58 this probe's +7s census collided with nv-stackdump's +8s
 * full dump (SuspendThreadByPeer timeout, ART suspend watchdog
 * SIGABRT'd the guest). Names now come from root ThreadGroup
 * enumeration, which suspends nobody; the remaining suspender
 * (nv-stackdump) serializes on [DiagSuspendGate]. (2) Each sample
 * also records the identity of ActivityManager.getService() and of
 * the IActivityManagerSingleton's mInstance: launch59 proved a
 * guest-initiated startActivity reached the real system AMS
 * unrewritten and the engine's AMS proxy never saw it, so the
 * samples show whether the proxy is installed in the guest process
 * at all, and if so from when.
 */
object DiagSuspendGate {
    /** Serializes diagnostic Thread.getAllStackTraces() calls. */
    val lock = Any()
}

object StateProbe {

    private val started = AtomicBoolean(false)

    // SecNeo H.d ciphertexts of the gate keys, copied from the
    // restored dex (WelcomeClient.startUp / .checkYinsiDialog,
    // CumpDoubleActiveManager.getDoubleActiveUrl). Decryption is
    // done by the guest's own H.d at probe time.
    private const val KEY_VIDEO_FLAG =
        "G7C8DDC19B03D9478B5319E4DE5DAD0C36891C12CB634AE26CD0F9958FBEBC4"
    private const val KEY_JIANBAN = "G4B82C613BC13BE3AF2019D"
    private const val KEY_INIT_DIRECT = "G6182C629B73FBC10EF008341"
    private const val KEY_CUMP_FLAG =
        "G44AAFB338F02840ED42FBD6DCDC1ECE24BAFF0258C07821DC526"

    // v40: WelcomeClient.enter() branch inputs, ciphertexts copied
    // from the restored dex (enter @000a guide flag via this.preference,
    // enter @0032 ad-switch string via App.getSharePreferenceUtil).
    private const val KEY_ENTER_GUIDE =
        "G6090E612B0279C2CEA0D9F45F7C2D6DE6D86"
    private const val KEY_ENTER_ADSWITCH =
        "G7C8DDC19B03D9428F61EAF45F3ECCDE87D9AC51F"

    fun schedule(packageName: String, filesDir: File) {
        if (packageName != "com.sinovatech.unicom.ui") return
        if (!started.compareAndSet(false, true)) return
        Thread {
            try {
                val pid = android.os.Process.myPid()
                val log = File(filesDir, "stateprobe-$pid.log")
                val marks = listOf(
                    2_000L to "t+2s", 7_000L to "t+7s",
                    15_000L to "t+15s", 30_000L to "t+30s",
                    60_000L to "t+60s", 120_000L to "t+120s"
                )
                var elapsed = 0L
                for ((at, label) in marks) {
                    val wait = at - elapsed
                    if (wait > 0) Thread.sleep(wait)
                    elapsed = at
                    try {
                        sample(log, label)
                    } catch (_: Throwable) {
                        // one bad sample must not kill the rest
                    }
                }
            } catch (_: Throwable) {
                // diagnostics must never disturb the guest
            }
        }.apply { isDaemon = true; name = "nv-stateprobe" }.start()
    }

    private fun fieldOf(cls: Class<*>, name: String): Field {
        var c: Class<*>? = cls
        while (c != null) {
            try {
                return c.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
        throw NoSuchFieldException(name + " on " + cls.name)
    }

    private fun boolField(obj: Any?, cls: Class<*>, name: String): String {
        return try {
            fieldOf(cls, name).getBoolean(obj).toString()
        } catch (e: Throwable) {
            "<" + e.javaClass.simpleName + ">"
        }
    }

    private fun objField(obj: Any?, cls: Class<*>, name: String): Any? {
        return try {
            fieldOf(cls, name).get(obj)
        } catch (_: Throwable) {
            null
        }
    }

    private fun describeDisposable(d: Any?): String {
        if (d == null) return "null"
        var disposed = "?"
        try {
            disposed = d.javaClass.getMethod("isDisposed")
                .invoke(d)?.toString() ?: "?"
        } catch (_: Throwable) {
            // not a Disposable-shaped object; class name is enough
        }
        return d.javaClass.name + "(disposed=" + disposed + ")"
    }

    /** v42: class name, plus JDK-proxy handler identity when proxied. */
    private fun describeAms(o: Any?): String {
        if (o == null) return "null"
        val cls = o.javaClass
        return if (java.lang.reflect.Proxy.isProxyClass(cls)) {
            val handler = try {
                java.lang.reflect.Proxy.getInvocationHandler(o)
            } catch (_: Throwable) {
                null
            }
            cls.name + " handler=" + (handler?.javaClass?.name ?: "?")
        } else {
            cls.name
        }
    }

    /**
     * v42: all thread names via the root ThreadGroup. enumerate()
     * copies live Thread references without suspending any thread,
     * unlike Thread.getAllStackTraces(). The array is sized
     * generously and retried larger if it filled exactly (the only
     * case where enumerate() silently truncates).
     */
    private fun threadNamesNoSuspend(): List<String> {
        var group = Thread.currentThread().threadGroup
        while (group?.parent != null) {
            group = group.parent
        }
        if (group == null) return emptyList()
        var capacity = maxOf(64, group.activeCount() * 2 + 16)
        for (attempt in 0 until 3) {
            val arr = arrayOfNulls<Thread>(capacity)
            val n = group.enumerate(arr, true)
            if (n < capacity) {
                return arr.take(n).mapNotNull { it?.name }.sorted()
            }
            capacity *= 2
        }
        return emptyList()
    }

    private fun sample(log: File, label: String) {
        val sb = StringBuilder()
        sb.append("==== ").append(label).append(" ====\n")
        fun line(s: String) {
            sb.append(s).append('\n')
        }
        try {
            val atCls = Class.forName("android.app.ActivityThread")
            val at = atCls.getMethod("currentActivityThread").invoke(null)
            if (at == null) {
                line("ActivityThread: null")
                log.appendText(sb.toString())
                return
            }
            val app = atCls.getMethod("getApplication").invoke(at)
                as? android.app.Application
            line("Application = " + (app?.javaClass?.name ?: "null"))
            val guestCl = app?.javaClass?.classLoader

            // ---- v42: AMS identity in THIS (guest) process ----
            // The real AMS is an IActivityManager$Stub$Proxy; the
            // engine's replacement is a JDK dynamic proxy handled by
            // ActivityManagerProxy. launch59: the guest's own
            // startActivity bypassed the proxy entirely, so record
            // what getService() and the singleton actually hold.
            try {
                val amCls = Class.forName("android.app.ActivityManager")
                val svc = amCls.getMethod("getService").invoke(null)
                line("ams.getService = " + describeAms(svc))
                val singletonFieldName =
                    if (android.os.Build.VERSION.SDK_INT >= 26) {
                        "IActivityManagerSingleton"
                    } else {
                        "gDefault"
                    }
                val sf = amCls.getDeclaredField(singletonFieldName)
                    .apply { isAccessible = true }
                val singleton = sf.get(null)
                val mf = Class.forName("android.util.Singleton")
                    .getDeclaredField("mInstance")
                    .apply { isAccessible = true }
                val inst = if (singleton == null) null else mf.get(singleton)
                line("ams.singletonInstance = " + describeAms(inst) +
                    " sameAsGetService=" + (inst != null && inst === svc))
            } catch (e: Throwable) {
                line("ams identity: <" + e.javaClass.simpleName + "> " +
                    e.message)
            }
            // ---- v43: self-test the proxy chain in THIS process ----
            // Read the ActivityManagerProxy invoke() witness, call a
            // harmless AMS method through ActivityManager.getService()
            // (the same reference guest code would use), re-read.
            // If our own call moves the counter but the counter never
            // moves between samples while the app is active, guest
            // code is not reaching AMS through this singleton at all;
            // if it does move between samples, only the startActivity
            // path bypasses (hijack execStartActivity channel).
            try {
                val witness = com.nextvm.core.binder.proxy
                    .ActivityManagerProxy
                val before = witness.invokeCount.get()
                var testResult = "svc=null"
                val amCls2 = Class.forName("android.app.ActivityManager")
                val svc2 = amCls2.getMethod("getService").invoke(null)
                if (svc2 != null) {
                    val r = svc2.javaClass
                        .getMethod("getRunningAppProcesses")
                        .invoke(svc2)
                    testResult = if (r is List<*>) {
                        "ok list size=" + r.size
                    } else {
                        "ok -> " + r
                    }
                }
                line("ams.witness before=" + before +
                    " selfTest=getRunningAppProcesses " + testResult +
                    " after=" + witness.invokeCount.get() +
                    " lastMethod=" + witness.lastInvokeMethod)
            } catch (e: Throwable) {
                line("ams.witness: <" + e.javaClass.simpleName + "> " +
                    e.message)
            }
            try {
                val h = objField(at, atCls, "mH")
                line("ActivityThread.mH = " +
                    (h?.javaClass?.name ?: "null"))
                val instr = objField(at, atCls, "mInstrumentation")
                line("ActivityThread.mInstrumentation = " +
                    (instr?.javaClass?.name ?: "null"))
            } catch (e: Throwable) {
                line("ActivityThread hooks: <" +
                    e.javaClass.simpleName + ">")
            }

            // ---- locate the WelcomeClient instance in mActivities ----
            var welcome: Any? = null
            try {
                val actsAny = fieldOf(atCls, "mActivities").get(at)
                if (actsAny == null) {
                    line("mActivities = null")
                } else {
                    val entries = actsAny.javaClass.getMethod("entrySet")
                        .invoke(actsAny) as java.util.Set<*>
                    line("mActivities.size = " + entries.size)
                    for (entry in entries) {
                        if (entry == null) continue
                        val rec = entry.javaClass.getMethod("getValue").invoke(entry)
                            ?: continue
                        val act = objField(rec, rec.javaClass, "activity") ?: continue
                        val nm = act.javaClass.name
                        line("  activity: " + nm)
                        if (nm == "com.sinovatech.unicom.basic.ui.activity.WelcomeClient") {
                            welcome = act
                        }
                    }
                }
            } catch (e: Throwable) {
                line("mActivities walk: <" + e.javaClass.simpleName + "> " + e.message)
            }

            // ---- WelcomeClient gate state ----
            val wc = welcome
            if (wc == null) {
                line("WelcomeClient: NOT FOUND")
            } else {
                val wcCls = wc.javaClass
                line("WelcomeClient.isStartUp = " + boolField(wc, wcCls, "isStartUp"))
                line("WelcomeClient.hasToMain = " + boolField(wc, wcCls, "hasToMain"))
                line("WelcomeClient.isRunAPP = " + boolField(wc, wcCls, "isRunAPP"))
                line("WelcomeClient.configSuccess = " +
                    boolField(wc, wcCls, "configSuccess"))
                line("WelcomeClient.refreshOnlineSuccess = " +
                    boolField(wc, wcCls, "refreshOnlineSuccess"))
                line("WelcomeClient.pictureIsReady = " +
                    boolField(wc, wcCls, "pictureIsReady"))
                // v40: post-gate witnesses. isLoadAd/adUrlStartRequestTime
                // prove loadKaiPingData ran; the three managers are
                // assigned in init() before the request chains start, so
                // their null-ness brackets how far init() progressed.
                line("WelcomeClient.isLoadAd = " +
                    boolField(wc, wcCls, "isLoadAd"))
                line("WelcomeClient.isOutside = " +
                    boolField(wc, wcCls, "isOutside"))
                line("WelcomeClient.adUrlStartRequestTime = " +
                    objField(wc, wcCls, "adUrlStartRequestTime"))
                for (mgrName in listOf(
                    "managerWelcome", "managerMainLogin", "configManager",
                    "userManager")) {
                    val mv = objField(wc, wcCls, mgrName)
                    line("WelcomeClient." + mgrName + " = " +
                        (mv?.javaClass?.name ?: "null"))
                }
                line("WelcomeClient.disposableConfig = " +
                    describeDisposable(objField(wc, wcCls, "disposableConfig")))
                line("WelcomeClient.disposableOnline = " +
                    describeDisposable(objField(wc, wcCls, "disposableOnline")))
                line("WelcomeClient.disposableTime = " +
                    describeDisposable(objField(wc, wcCls, "disposableTime")))
                // activity facts the first onCreate gate consumes
                try {
                    line("WelcomeClient.isTaskRoot = " +
                        wcCls.getMethod("isTaskRoot").invoke(wc))
                } catch (e: Throwable) {
                    line("isTaskRoot: <" + e.javaClass.simpleName + "> " + e.message)
                }
                try {
                    line("WelcomeClient.isFinishing = " +
                        wcCls.getMethod("isFinishing").invoke(wc) +
                        " isDestroyed = " +
                        wcCls.getMethod("isDestroyed").invoke(wc))
                } catch (e: Throwable) {
                    line("isFinishing: <" + e.javaClass.simpleName + ">")
                }
                try {
                    val intent = wcCls.getMethod("getIntent").invoke(wc)
                    if (intent == null) {
                        line("WelcomeClient.intent = null")
                    } else {
                        val ic = intent.javaClass
                        line(
                            "WelcomeClient.intent action=" +
                                ic.getMethod("getAction").invoke(intent) +
                                " scheme=" +
                                ic.getMethod("getScheme").invoke(intent) +
                                " categories=" +
                                ic.getMethod("getCategories").invoke(intent)
                        )
                    }
                } catch (e: Throwable) {
                    line("intent: <" + e.javaClass.simpleName + "> " + e.message)
                }
                // the exact SharePreferenceUtil the gate code uses
                val pref = objField(wc, wcCls, "preference")
                if (pref != null) {
                    readGateKeys({ s -> line(s) }, pref, guestCl)
                } else {
                    line("WelcomeClient.preference = null")
                }
            }

            // ---- statics on the request path ----
            if (guestCl != null) {
                try {
                    val mmc = Class.forName(
                        "com.sinovatech.unicom.basic.ui.manager.ManagerMainConfig",
                        false, guestCl)
                    line("ManagerMainConfig.isForExit = " +
                        boolField(null, mmc, "isForExit"))
                } catch (e: Throwable) {
                    line("ManagerMainConfig: <" + e.javaClass.simpleName + ">")
                }
                try {
                    val appCls = Class.forName(
                        "com.sinovatech.unicom.ui.App", false, guestCl)
                    line("App.qidongFlag = " + objField(null, appCls, "qidongFlag"))
                    line("App.refreshbackisRequest = " +
                        boolField(null, appCls, "refreshbackisRequest"))
                } catch (e: Throwable) {
                    line("App statics: <" + e.javaClass.simpleName + ">")
                }
                // ---- ad manager singleton: video-branch witness ----
                try {
                    val mgrCls = Class.forName(
                        "com.sinovatech.unicom.separatemodule.advtise" +
                            ".admanager.UnicomAdmanger", false, guestCl)
                    val mgr = objField(null, mgrCls, "admanger")
                    if (mgr == null) {
                        line("UnicomAdmanger.admanger = null (getInstance never ran)")
                    } else {
                        line("UnicomAdmanger.videoPlaying = " +
                            boolField(mgr, mgrCls, "videoPlaying"))
                        line("UnicomAdmanger.subscribe = " +
                            describeDisposable(objField(mgr, mgrCls, "subscribe")))
                        val ref = objField(mgr, mgrCls, "activityContext")
                        val target = try {
                            ref?.javaClass?.getMethod("get")?.invoke(ref)
                        } catch (_: Throwable) {
                            null
                        }
                        line("UnicomAdmanger.activityContext -> " +
                            (target?.javaClass?.name ?: "null"))
                    }
                } catch (e: Throwable) {
                    line("UnicomAdmanger: <" + e.javaClass.simpleName + "> " + e.message)
                }
                // ---- v40: replay enter()'s first statement ----
                // enter() opens with ServiceDataUtils
                // .getAllServicePublishVersionString(); if that throws
                // in the sandbox, enter() dies before any branch and
                // the Rx consumer swallows it silently. Invoke the
                // same static here and record the outcome verbatim.
                try {
                    val sdCls = Class.forName(
                        "com.sinovatech.unicom.basic.utils.ServiceDataUtils",
                        false, guestCl)
                    val m = sdCls.getMethod(
                        "getAllServicePublishVersionString")
                    val r = m.invoke(null)
                    line("enterReplay.getAllServicePublishVersionString = '" +
                        r + "'")
                } catch (e: Throwable) {
                    val cause = (e as? java.lang.reflect.InvocationTargetException)
                        ?.targetException ?: e
                    line("enterReplay.getAllServicePublishVersionString " +
                        "THREW <" + cause.javaClass.name + "> " + cause.message)
                }
                // ---- SoulPermission top activity: dialog-branch witness ----
                try {
                    val spCls = Class.forName(
                        "com.qw.soul.permission.SoulPermission", false, guestCl)
                    val sp = spCls.getMethod("getInstance").invoke(null)
                    val top = spCls.getMethod("getTopActivity").invoke(sp)
                    line(
                        "SoulPermission.getTopActivity = " +
                            (top?.javaClass?.name ?: "null") +
                            " sameAsWelcome=" + (top != null && top === welcome)
                    )
                } catch (e: Throwable) {
                    val cause = (e as? java.lang.reflect.InvocationTargetException)
                        ?.targetException ?: e
                    line("SoulPermission: <" + cause.javaClass.name + "> " +
                        cause.message)
                }
            }

            // ---- thread census: did the 6s timer / loopj ever exist? ----
            // v42: names via root ThreadGroup enumeration — unlike
            // getAllStackTraces() this suspends nobody (launch58's
            // census/stackdump suspension collision SIGABRT'd the
            // guest; see DiagSuspendGate).
            try {
                val names = threadNamesNoSuspend()
                line("threads(" + names.size + ") = " + names.joinToString(","))
            } catch (e: Throwable) {
                line("threads: <" + e.javaClass.simpleName + ">")
            }
        } catch (e: Throwable) {
            line("sample aborted <" + e.javaClass.simpleName + "> " + e.message)
        }
        try {
            log.appendText(sb.toString())
        } catch (_: Throwable) {
            // diagnostics must never disturb the guest
        }
    }

    private fun readGateKeys(
        line: (String) -> Unit,
        pref: Any,
        guestCl: ClassLoader?
    ) {
        var decrypt: ((String) -> String)? = null
        if (guestCl != null) {
            try {
                val h = Class.forName("com.secneo.apkwrapper.H", false, guestCl)
                val d = h.getMethod("d", String::class.java)
                decrypt = { s -> d.invoke(null, s) as? String ?: s }
            } catch (e: Throwable) {
                line("H.d unavailable: <" + e.javaClass.simpleName + ">")
            }
        }
        val getBool = try {
            pref.javaClass.getMethod("getBoolean", String::class.java)
        } catch (_: Throwable) {
            null
        }
        val getStr = try {
            pref.javaClass.getMethod("getString", String::class.java)
        } catch (_: Throwable) {
            null
        }
        fun key(ct: String): String = try {
            decrypt?.invoke(ct) ?: ct
        } catch (e: Throwable) {
            ct + " <decrypt " + e.javaClass.simpleName + ">"
        }
        fun boolKey(labelName: String, ct: String) {
            val k = key(ct)
            val v = try {
                getBool?.invoke(pref, k)?.toString() ?: "<no method>"
            } catch (e: Throwable) {
                val cause = (e as? java.lang.reflect.InvocationTargetException)
                    ?.targetException ?: e
                "<" + cause.javaClass.simpleName + ">"
            }
            line("pref[$labelName] key='" + k + "' = " + v)
        }
        boolKey("K0-videoFlag", KEY_VIDEO_FLAG)
        boolKey("keyA-jianban", KEY_JIANBAN)
        boolKey("keyB-initDirect", KEY_INIT_DIRECT)
        val k = key(KEY_CUMP_FLAG)
        val v = try {
            getStr?.invoke(pref, k)?.toString() ?: "<no method>"
        } catch (e: Throwable) {
            val cause = (e as? java.lang.reflect.InvocationTargetException)
                ?.targetException ?: e
            "<" + cause.javaClass.simpleName + ">"
        }
        line("pref[cumpFlag] key='" + k + "' = '" + v + "'")
        // v40: enter()'s two branch inputs
        boolKey("enterGuideFlag", KEY_ENTER_GUIDE)
        val k2 = key(KEY_ENTER_ADSWITCH)
        val v2 = try {
            getStr?.invoke(pref, k2)?.toString() ?: "<no method>"
        } catch (e: Throwable) {
            val cause = (e as? java.lang.reflect.InvocationTargetException)
                ?.targetException ?: e
            "<" + cause.javaClass.simpleName + ">"
        }
        line("pref[enterAdSwitch] key='" + k2 + "' = '" + v2 + "'")
    }
}
