package com.nextvm.core.binder.proxy

import android.content.pm.ShortcutInfo
import android.graphics.Bitmap
import android.graphics.drawable.Icon
import timber.log.Timber

/**
 * v110 probe, kept in v111 as a gate witness.
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
 * In v111 it is called BEFORE the gate, so a run that still crashes
 * with 0 probe lines would mean the call never reached the proxy at
 * all, while probe lines with isVirtual=false/orArgs=true prove the
 * parameter gate (not the pid gate) let the sanitizer run.
 */
internal object ShortcutProbe {
    private const val TAG = "ShortcutProbe"

    /**
     * v111: called BEFORE the isVirtual gate, so the log itself proves
     * whether the gate passed. isVirtual is the pidToInstance check
     * (launch136: always false in a guest process, registerProcessPid
     * is never called); orArgs is the isVirtualCallOrArgs fallback
     * (any String argument is a known virtual package).
     */
    fun log(methodName: String, args: Array<out Any>?, isVirtual: Boolean, orArgs: Boolean) {
        if (args == null) {
            Timber.tag(TAG).i("%s args=null isVirtual=%b orArgs=%b", methodName, isVirtual, orArgs)
            return
        }
        val classes = args.joinToString(",") { it?.javaClass?.name ?: "null" }
        val strings = args.filterIsInstance<String>().joinToString(",")
        Timber.tag(TAG).i("%s argc=%d isVirtual=%b orArgs=%b classes=[%s] strings=[%s]",
            methodName, args.size, isVirtual, orArgs, classes, strings)
        for (arg in args) {
            when {
                arg is List<*> -> logList(arg)
                arg != null && arg.javaClass.name ==
                    "android.content.pm.ParceledListSlice" -> {
                    val list = sliceList(arg)
                    if (list == null) {
                        Timber.tag(TAG).i("slice: cannot extract list")
                    } else {
                        Timber.tag(TAG).i("slice: size=%d", list.size)
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
                Timber.tag(TAG).i("entry %d: not ShortcutInfo (%s)", index,
                    item?.javaClass?.name ?: "null")
                continue
            }
            val id = try { item.id } catch (_: Throwable) { "?" }
            val icon = getIcon(item)
            if (icon == null) {
                Timber.tag(TAG).i("entry %d id=%s icon=null", index, id)
            } else {
                val type = try { icon.type } catch (_: Throwable) { -1 }
                val bitmap = getBitmap(icon)
                if (bitmap == null) {
                    Timber.tag(TAG).i(
                        "entry %d id=%s iconType=%d bitmap=null", index, id, type)
                } else {
                    val state = try {
                        "recycled=${bitmap.isRecycled} " +
                            "w=${bitmap.width} h=${bitmap.height} " +
                            "config=${bitmap.config}"
                    } catch (t: Throwable) {
                        "unreadable: ${t.javaClass.simpleName}"
                    }
                    Timber.tag(TAG).i(
                        "entry %d id=%s iconType=%d bitmap: %s",
                        index, id, type, state)
                }
            }
            val intentDropped = try {
                val intent = item.intent
                if (intent == null) "intent=null"
                else "intentDropped=${IntentParcelSanitizer.sanitize(intent).dropped}"
            } catch (t: Throwable) {
                "intentUnreadable: ${t.javaClass.simpleName}"
            }
            Timber.tag(TAG).i("entry %d id=%s %s", index, id, intentDropped)
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
