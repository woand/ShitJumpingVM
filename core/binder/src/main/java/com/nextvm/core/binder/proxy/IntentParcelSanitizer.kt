package com.nextvm.core.binder.proxy

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.util.SparseArray
import timber.log.Timber

/**
 * Removes parcelable values which are already invalid before a rewritten
 * guest Intent is sent back through ActivityTaskManager.
 *
 * A guest can retain a recycled Bitmap in an Intent extra.  The object is
 * harmless while it stays in Java, but Bitmap.writeToParcel() dereferences
 * its native peer and can take the whole guest process down.  This sanitizer
 * is deliberately used only on the virtual-routing copy of an Intent; an
 * ordinary Binder call is still forwarded byte-for-byte.
 */
internal object IntentParcelSanitizer {
    private const val TAG = "IntentParcel"
    private const val MAX_DEPTH = 8

    data class Result(
        val intent: Intent,
        val dropped: Int
    )

    fun sanitize(intent: Intent): Result {
        val copy = Intent(intent)
        val extras = try {
            copy.extras
        } catch (t: Throwable) {
            // A malformed/lazy Bundle is safer to omit than to parcel again.
            Timber.tag(TAG).w(t, "dropping unreadable Intent extras")
            copy.replaceExtras(null)
            return Result(copy, 1)
        } ?: return Result(copy, 0)

        val cleaned = sanitizeBundle(extras, 0)
        if (cleaned.dropped != 0) {
            copy.replaceExtras(cleaned.bundle)
            Timber.tag(TAG).w(
                "removed %d invalid Parcelable value(s) from routed Intent",
                cleaned.dropped
            )
        }
        return Result(copy, cleaned.dropped)
    }

    private data class BundleResult(
        val bundle: Bundle,
        val dropped: Int
    )

    private fun sanitizeBundle(source: Bundle, depth: Int): BundleResult {
        if (depth > MAX_DEPTH) {
            return BundleResult(Bundle(), 1)
        }

        val copy = try {
            Bundle(source)
        } catch (t: Throwable) {
            Timber.tag(TAG).w(t, "dropping unreadable nested Bundle")
            return BundleResult(Bundle(), 1)
        }

        var dropped = 0
        val keys = try {
            source.keySet().toList()
        } catch (t: Throwable) {
            Timber.tag(TAG).w(t, "dropping Bundle with unreadable keys")
            return BundleResult(Bundle(), 1)
        }

        for (key in keys) {
            val value = try {
                copy.get(key)
            } catch (t: Throwable) {
                copy.remove(key)
                dropped++
                continue
            }

            if (value is Bundle) {
                val nested = sanitizeBundle(value, depth + 1)
                copy.putBundle(key, nested.bundle)
                dropped += nested.dropped
            } else if (containsInvalidBitmap(value, depth + 1)) {
                // Keep the surrounding Bundle type intact, but remove the
                // single unsafe key rather than changing its value's type.
                copy.remove(key)
                dropped++
            }
        }
        return BundleResult(copy, dropped)
    }

    private fun containsInvalidBitmap(value: Any?, depth: Int): Boolean {
        if (value == null) return false
        if (depth > MAX_DEPTH) return true

        return when (value) {
            is Bitmap -> try {
                value.isRecycled
            } catch (_: Throwable) {
                true
            }
            is Bundle -> bundleContainsInvalidBitmap(value, depth)
            is Array<*> -> value.any { containsInvalidBitmap(it, depth + 1) }
            is Iterable<*> -> value.any { containsInvalidBitmap(it, depth + 1) }
            is SparseArray<*> -> {
                (0 until value.size()).any {
                    containsInvalidBitmap(value.valueAt(it), depth + 1)
                }
            }
            else -> false
        }
    }

    private fun bundleContainsInvalidBitmap(bundle: Bundle, depth: Int): Boolean {
        val keys = try {
            bundle.keySet()
        } catch (_: Throwable) {
            return true
        }
        for (key in keys) {
            val value = try {
                bundle.get(key)
            } catch (_: Throwable) {
                return true
            }
            if (containsInvalidBitmap(value, depth + 1)) return true
        }
        return false
    }
}
