package com.nextvm.core.binder.proxy

import android.content.pm.ShortcutInfo
import android.graphics.Bitmap
import android.graphics.drawable.Icon
import timber.log.Timber

/**
 * v110 probe only — diagnostic, not a fix. Remove in the fix version.
 *
 * Logs, for every shortcut-service call from a virtual app, the method
 * name, every argument's class name, and for each ShortcutInfo in a
 * List or ParceledListSlice: its id, its Icon type, and its Bitmap
 * state (null, isRecycled, width, height, config), plus whether its
 * Intent would be dropped by IntentParcelSanitizer.
 *
 * The probe never parcels a Bitmap and never modifies the arguments:
 * the caller forwards the original arguments unchanged after logging,
 * so the faulting input is observed exactly as the guest sent it.
 * This distinguishes the two launch133 explanations: "sanitizer ran
 * but the Bitmap looked valid in Java" vs "sanitizer never ran
 * because the argument shape did not match".
 */
internal object ShortcutProbe {
    private const val TAG = "ShortcutProbe"

    fun log(methodName: String, args: Array<out Any>?) {
        if (args == null) {
            Timber.tag(TAG).i("%s args=null", methodName)
            return
        }
        val classes = args.joinToString(",") { it?.javaClass?.name ?: "null" }
        Timber.tag(TAG).i("%s argc=%d classes=[%s]", methodName, args.size, classes)
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
