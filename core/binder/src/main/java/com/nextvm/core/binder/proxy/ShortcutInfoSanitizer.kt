package com.nextvm.core.binder.proxy

import android.content.pm.ShortcutInfo
import android.graphics.Bitmap
import android.graphics.drawable.Icon
import timber.log.Timber

/**
 * v108: drop ShortcutInfo entries whose Icon Bitmap cannot be parceled,
 * before they reach IShortcutService. Everything else passes through
 * byte-for-byte — this is not a shortcut blocker.
 *
 * Launch131 evidence: guest ShortcutManagerHelper.onResFailed called
 * ShortcutManager.setDynamicShortcuts, and the system-side parceling died
 * in Bitmap.writeToParcel -> AParcel_writeInt32 with a null AParcel
 * (fault 0x8). The shortcut proxy itself only rewrote package-name
 * Strings, so the bad Bitmap arrived in the guest's ShortcutInfo.
 *
 * A recycled Bitmap is the only invalid state detectable from Java:
 * its native peer is gone, so nativeWriteToParcel dereferences it.
 * A ShortcutInfo whose Intent extras contain an invalid Bitmap is
 * dropped whole (rebuilding ShortcutInfo with a sanitized Intent would
 * change its identity); IntentParcelSanitizer is used only as a detector
 * here, its copy is discarded.
 *
 * Note: ShortcutInfo.getIcon() and Icon.getBitmap() are hidden from the
 * SDK stub (javap on android-35 confirms neither is in the stub), so
 * both are reached by reflection. The guest process already runs the
 * LSPosed hidden-API bypass, so reflection on these public framework
 * methods works at runtime. If reflection fails, the entry is dropped
 * rather than forwarded uninspected — a dropped shortcut cannot crash
 * the guest, an uninspected one can.
 */
internal object ShortcutInfoSanitizer {
    private const val TAG = "ShortcutInfo"

    fun sanitize(shortcuts: List<ShortcutInfo>): List<ShortcutInfo> {
        var dropped = 0
        val kept = ArrayList<ShortcutInfo>(shortcuts.size)
        for (info in shortcuts) {
            if (hasInvalidBitmap(info)) {
                dropped++
                continue
            }
            kept.add(info)
        }
        if (dropped != 0) {
            Timber.tag(TAG).w(
                "dropped %d invalid ShortcutInfo(s) before setDynamicShortcuts",
                dropped
            )
        }
        return kept
    }

    /**
     * v109: ShortcutManager.setDynamicShortcuts wraps the List in a
     * ParceledListSlice before calling IShortcutService, so the proxy
     * receives a slice, not a List (this is why v108 never ran: its
     * List-only branch never matched). ParceledListSlice is hidden
     * from the SDK stub, so it is handled purely by reflection and
     * identified by class name, never imported.
     *
     * Returns: the original slice when nothing is dropped, a new slice
     * wrapping the kept entries when some are dropped, or null when
     * every entry is dropped or the slice cannot be inspected —
     * in both null cases the caller must not call the service at all.
     */
    fun sanitizeSlice(slice: Any): Any? {
        val list = extractSliceList(slice)
        if (list == null) {
            Timber.tag(TAG).w("cannot inspect ParceledListSlice, dropping call")
            return null
        }
        if (list.isEmpty() || list[0] !is ShortcutInfo) return slice
        @Suppress("UNCHECKED_CAST")
        val kept = sanitize(list as List<ShortcutInfo>)
        if (kept.isEmpty()) return null
        if (kept.size == list.size) return slice
        return try {
            slice.javaClass.getConstructor(List::class.java).newInstance(kept)
        } catch (e: Throwable) {
            Timber.tag(TAG).w(e, "cannot repack ParceledListSlice, dropping call")
            null
        }
    }

    private fun extractSliceList(slice: Any): List<*>? {
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

    private fun hasInvalidBitmap(info: ShortcutInfo): Boolean {
        try {
            val icon = getIcon(info) ?: return false
            if (isInvalidIconBitmap(icon)) return true
        } catch (_: Throwable) {
            return true
        }
        try {
            val intent = info.intent ?: return false
            if (IntentParcelSanitizer.sanitize(intent).dropped != 0) return true
        } catch (_: Throwable) {
            return true
        }
        return false
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
        } catch (e: Throwable) {
            // Both reflection paths failed: the caller treats this as
            // invalid (drop) rather than forwarding uninspected.
            throw IllegalStateException("cannot read ShortcutInfo icon", e)
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

    private fun isInvalidIconBitmap(icon: Icon): Boolean {
        val type = try {
            icon.type
        } catch (_: Throwable) {
            return true
        }
        val bitmap = getBitmap(icon)
        if (bitmap == null) {
            // Only bitmap-typed icons need a Bitmap; URI/data/resource
            // icons parcel a string/bytes, not a Bitmap object.
            return type == Icon.TYPE_BITMAP || type == Icon.TYPE_ADAPTIVE_BITMAP
        }
        return try {
            bitmap.isRecycled || bitmap.width <= 0 || bitmap.height <= 0
        } catch (_: Throwable) {
            true
        }
    }
}
