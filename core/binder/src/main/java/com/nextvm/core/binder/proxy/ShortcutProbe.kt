package com.nextvm.core.binder.proxy

import android.content.pm.ShortcutInfo
import android.graphics.Bitmap
import android.graphics.drawable.Icon
import android.util.Log

/**
 * v110 probe, kept in v111 as a gate witness, rerouted in v112.
 *
 * v112 reroute rationale: the Timber-tagged probe produced 0 lines
 * in launches 134–137 even in a run (launch137) whose stackdump proves
 * handleMethod reached the gate, while Timber-tagged SvcProxyMgr
 * lines do reach logcat. The probe therefore bypasses Timber
 * entirely and uses android.util.Log directly under the proven
 * SvcProxyMgr tag, prefixed "ShortcutProbe: ", so a missing line
 * can no longer be blamed on the Timber tag.
 *
 * Logs, for every shortcut-service call, the method name, every
 * argument's class name, the String arguments (package names), the
 * isVirtual pid-gate value and the isVirtualCallOrArgs fallback
 * value, and for each ShortcutInfo in a List or ParceledListSlice:
 * its id, its Icon type, and its Bitmap state (null, isRecycled,
 * width, height, config), plus whether its Intent would be dropped
 * by IntentParcelSanitizer.
 *
 * The probe never parcels a Bitmap and never modifies the arguments.
 */
internal object ShortcutProbe {
    private fun i(msg: String) {
        try {
            Log.i("SvcProxyMgr", "ShortcutProbe: $msg")
        } catch (_: Throwable) {
            // Probe must never disturb the guest call.
        }
    }

    /**
     * v111: called BEFORE the isVirtual gate, so the log itself proves
     * whether the gate passed. isVirtual is the pidToInstance check
     * (launch136: always false in a guest process, registerProcessPid
     * is never called); orArgs is the isVirtualCallOrArgs fallback
     * (any String argument is a known virtual package).
     * v112: the gate is gone for shortcut methods (see handleMethod),
     * but both values are still logged for the record.
     */
    fun log(methodName: String, args: Array<out Any>?, isVirtual: Boolean, orArgs: Boolean) {
        if (args == null) {
            i("$methodName args=null isVirtual=$isVirtual orArgs=$orArgs")
            return
        }
        val classes = args.joinToString(",") { it?.javaClass?.name ?: "null" }
        val strings = args.filterIsInstance<String>().joinToString(",")
        i("$methodName argc=${args.size} isVirtual=$isVirtual orArgs=$orArgs classes=[$classes] strings=[$strings]")
        for (arg in args) {
            when {
                arg is List<*> -> logList(arg)
                arg != null && arg.javaClass.name ==
                    "android.content.pm.ParceledListSlice" -> {
                    val list = sliceList(arg)
                    if (list == null) {
                        i("slice: cannot extract list")
                    } else {
                        i("slice: size=${list.size}")
                        logList(list)
                    }
                }
            }
        }
    }

    private fun sliceList(slice: Any): List<*>? {
        try {
            val method = slice.javaClass.getMethod("getList")
            val result = method.invoke(slice)
            if (result is List<*>) return result
        } catch (_: Throwable) {
            // Fall through to field access.
        }
        var clazz: Class<*>? = slice.javaClass
        while (clazz != null) {
            try {
                val field = clazz.getDeclaredField("mList")
                field.isAccessible = true
                val result = field.get(slice)
                if (result is List<*>) return result
                return null
            } catch (_: Throwable) {
                clazz = clazz.superclass
            }
        }
        return null
    }

    private fun logList(list: List<*>) {
        for ((index, item) in list.withIndex()) {
            if (item !is ShortcutInfo) {
                i("entry $index: not ShortcutInfo (${item?.javaClass?.name ?: "null"})")
                continue
            }
            val id = try { item.id } catch (_: Throwable) { "?" }
            val icon = getIcon(item)
            if (icon == null) {
                i("entry $index id=$id icon=null")
            } else {
                val type = try { icon.type } catch (_: Throwable) { -1 }
                val bitmap = getBitmap(icon)
                if (bitmap == null) {
                    i("entry $index id=$id iconType=$type bitmap=null")
                } else {
                    val state = try {
                        "recycled=${bitmap.isRecycled} " +
                            "w=${bitmap.width} h=${bitmap.height} " +
                            "config=${bitmap.config}"
                    } catch (t: Throwable) {
                        "unreadable: ${t.javaClass.simpleName}"
                    }
                    i("entry $index id=$id iconType=$type bitmap: $state")
                }
            }
            val intentDropped = try {
                val intent = item.intent
                if (intent == null) "intent=null"
                else "intentDropped=${IntentParcelSanitizer.sanitize(intent).dropped}"
            } catch (t: Throwable) {
                "intentUnreadable: ${t.javaClass.simpleName}"
            }
            i("entry $index id=$id $intentDropped")
        }
    }

    private fun getIcon(info: ShortcutInfo): Icon? {
        try {
            val method = ShortcutInfo::class.java.getMethod("getIcon")
            return method.invoke(info) as? Icon
        } catch (_: Throwable) {
            // Fall through to field access.
        }
        return try {
            val field = ShortcutInfo::class.java.getDeclaredField("mIcon")
            field.isAccessible = true
            field.get(info) as? Icon
        } catch (_: Throwable) {
            null
        }
    }

    private fun getBitmap(icon: Icon): Bitmap? {
        try {
            val method = Icon::class.java.getMethod("getBitmap")
            return method.invoke(icon) as? Bitmap
        } catch (_: Throwable) {
            // Fall through to field access.
        }
        return try {
            val field = Icon::class.java.getDeclaredField("mBitmap")
            field.isAccessible = true
            field.get(icon) as? Bitmap
        } catch (_: Throwable) {
            null
        }
    }
}
