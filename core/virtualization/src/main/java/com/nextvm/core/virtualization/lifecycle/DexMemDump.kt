package com.nextvm.core.virtualization.lifecycle

import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

/**
 * v37 (option B): dump dex images out of this process's own memory.
 *
 * The guest's payload dexes ship inside the APK with their method
 * bodies zeroed (SecNeo extraction: on disk, WelcomeClient.goMain /
 * runUnciomApp / enter / init / initConfig are NOP sleds). The shell
 * restores the real code in memory before ART executes it, so the
 * decrypted dex images should be sitting in this process's address
 * space (InMemoryDexClassLoader buffers / ART mappings). We scan
 * /proc/self/maps + /proc/self/mem for dex magic, validate each
 * candidate against the dex header, and write whole images to
 * dexmem-<pid>-<fileSize>-<hash>.dex next to the other guest
 * diagnostics. Offline, the dumped dex2 can then be disassembled to
 * read the gate logic that static analysis of the APK cannot see.
 *
 * Unicom only, once per process, two passes (+4s / +26s after bind)
 * so classes loaded late are covered by the second pass. Every
 * failure is swallowed: diagnostics must never disturb the guest.
 */
object DexMemDump {

    private val started = AtomicBoolean(false)
    private val dumpedKeys = HashSet<String>()

    fun schedule(packageName: String, filesDir: File) {
        if (packageName != "com.sinovatech.unicom.ui") return
        if (!started.compareAndSet(false, true)) return
        Thread {
            try {
                val pid = android.os.Process.myPid()
                val log = File(filesDir, "dexmem-$pid.log")
                Thread.sleep(4_000)
                runPass(pid, filesDir, log, "pass1(+4s)")
                Thread.sleep(22_000)
                runPass(pid, filesDir, log, "pass2(+26s)")
            } catch (_: Throwable) {
                // diagnostics must never disturb the guest
            }
        }.apply { isDaemon = true; name = "nv-dexdump" }.start()
    }

    private class Region(val start: Long, val end: Long, val name: String) {
        val size: Long get() = end - start
    }

    private fun listRegions(): List<Region> {
        val out = ArrayList<Region>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                try {
                    val parts = line.split(Regex("\\s+"), 6)
                    if (parts.size < 5) return@forEachLine
                    val range = parts[0].split("-")
                    if (range.size != 2) return@forEachLine
                    val start = range[0].toLong(16)
                    val end = range[1].toLong(16)
                    val perms = parts[1]
                    if (!perms.startsWith("r")) return@forEachLine
                    val name = if (parts.size >= 6) parts[5].trim() else ""
                    // Candidate homes for a decrypted dex image: anonymous
                    // mappings (heap byte[] / direct buffers / memfd-style),
                    // bracketed ART regions ([anon:dalvik-...], [heap]),
                    // memfd, or a plain .dex mapping. Device paths, .so/.oat
                    // images and the APK itself are skipped on purpose.
                    val nameOk = name.isEmpty() || name.startsWith("[") ||
                        name.contains("memfd") || name.endsWith(".dex")
                    if (!nameOk) return@forEachLine
                    if (end - start < 256L * 1024L) return@forEachLine
                    out.add(Region(start, end, name))
                } catch (_: Throwable) {
                    // skip malformed line
                }
            }
        } catch (_: Throwable) {
            // no regions -> empty pass
        }
        return out
    }

    private fun u32le(b: ByteArray, off: Int): Long {
        return (b[off].toLong() and 0xff) or
            ((b[off + 1].toLong() and 0xff) shl 8) or
            ((b[off + 2].toLong() and 0xff) shl 16) or
            ((b[off + 3].toLong() and 0xff) shl 24)
    }

    /** Returns dex file_size if a valid dex header starts at b[off], else -1. */
    private fun dexFileSizeAt(b: ByteArray, off: Int, avail: Int): Long {
        if (avail - off < 112) return -1
        // magic: "dex\n" + version "035\0".."040\0"
        if (b[off] != 0x64.toByte() || b[off + 1] != 0x65.toByte() ||
            b[off + 2] != 0x78.toByte() || b[off + 3] != 0x0a.toByte()
        ) return -1
        if (b[off + 4] != 0x30.toByte() || b[off + 5] != 0x33.toByte()) return -1
        val v3 = b[off + 6]
        if (v3 < 0x35.toByte() || v3 > 0x39.toByte()) return -1
        if (b[off + 7] != 0.toByte()) return -1
        val fileSize = u32le(b, off + 32)
        if (fileSize < 1_000_000L || fileSize > 40_000_000L) return -1
        if (u32le(b, off + 36) != 0x70L) return -1 // header_size
        if (u32le(b, off + 40) != 0x12345678L) return -1 // endian_tag
        val stringIds = u32le(b, off + 56)
        if (stringIds < 1_000L || stringIds > 2_000_000L) return -1
        val classDefs = u32le(b, off + 96)
        if (classDefs < 10L || classDefs > 200_000L) return -1
        return fileSize
    }

    private fun fnv1a(b: ByteArray, len: Int): Long {
        var h = -3750763034362895579L // 0xcbf29ce484222325
        var i = 0
        while (i < len) {
            h = h xor (b[i].toLong() and 0xff)
            h *= 1099511628211L // 0x100000001b3
            i++
        }
        return h
    }

    private fun containsBytes(hay: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || hay.size < needle.size) return false
        var i = 0
        val last = hay.size - needle.size
        while (i <= last) {
            if (hay[i] == needle[0]) {
                var j = 1
                while (j < needle.size && hay[i + j] == needle[j]) j++
                if (j == needle.size) return true
            }
            i++
        }
        return false
    }

    private fun runPass(pid: Int, dir: File, log: File, tag: String) {
        val welcome = "WelcomeClient".toByteArray(Charsets.US_ASCII)
        val cump = "CumpDoubleActiveManager".toByteArray(Charsets.US_ASCII)
        val sb = StringBuilder()
        sb.append("==== ").append(tag).append(" pid=").append(pid).append(" ====\n")
        var regions = 0
        var scanned = 0L
        var candidates = 0
        var written = 0
        var mem: RandomAccessFile? = null
        try {
            mem = RandomAccessFile("/proc/self/mem", "r")
            val chunk = ByteArray(4 * 1024 * 1024)
            for (region in listRegions()) {
                regions++
                try {
                    var pos = region.start
                    // Tail of the previous chunk, so a magic straddling the
                    // chunk boundary is still seen whole.
                    var carry = ByteArray(0)
                    while (pos < region.end) {
                        val want = minOf(chunk.size.toLong(), region.end - pos).toInt()
                        mem.seek(pos)
                        mem.readFully(chunk, 0, want)
                        scanned += want
                        val buf = ByteArray(carry.size + want)
                        System.arraycopy(carry, 0, buf, 0, carry.size)
                        System.arraycopy(chunk, 0, buf, carry.size, want)
                        val base = pos - carry.size
                        var i = 0
                        while (i + 112 <= buf.size) {
                            if (buf[i] == 0x64.toByte()) {
                                val fs = dexFileSizeAt(buf, i, buf.size)
                                if (fs > 0) {
                                    val addr = base + i
                                    candidates++
                                    if (addr + fs <= region.end) {
                                        val image = ByteArray(fs.toInt())
                                        mem.seek(addr)
                                        mem.readFully(image)
                                        val key = fs.toString() + "-" +
                                            java.lang.Long.toHexString(
                                                fnv1a(image, minOf(8192, image.size)))
                                        val hasW = containsBytes(image, welcome)
                                        val hasC = containsBytes(image, cump)
                                        var note = "dup"
                                        synchronized(dumpedKeys) {
                                            if (dumpedKeys.add(key)) {
                                                val outFile = File(
                                                    dir, "dexmem-$pid-$key.dex")
                                                outFile.writeBytes(image)
                                                written++
                                                note = "written " + outFile.name
                                            }
                                        }
                                        sb.append("candidate addr=0x")
                                            .append(java.lang.Long.toHexString(addr))
                                            .append(" region='").append(region.name)
                                            .append("' fileSize=").append(fs)
                                            .append(" welcome=").append(hasW)
                                            .append(" cump=").append(hasC)
                                            .append(" ").append(note).append("\n")
                                    } else {
                                        sb.append("candidate addr=0x")
                                            .append(java.lang.Long.toHexString(addr))
                                            .append(" fileSize=").append(fs)
                                            .append(" exceeds region, skipped\n")
                                    }
                                }
                            }
                            i++
                        }
                        val keep = minOf(128, want)
                        carry = buf.copyOfRange(buf.size - keep, buf.size)
                        pos += want
                    }
                } catch (_: Throwable) {
                    // region vanished or unreadable mid-scan: move on
                }
            }
        } catch (e: Throwable) {
            sb.append("pass aborted <").append(e.javaClass.simpleName)
                .append("> ").append(e.message).append("\n")
        } finally {
            try { mem?.close() } catch (_: Throwable) {}
        }
        sb.append("regions=").append(regions)
            .append(" scannedMB=").append(scanned / (1024 * 1024))
            .append(" candidates=").append(candidates)
            .append(" written=").append(written).append("\n")
        try {
            log.appendText(sb.toString())
        } catch (_: Throwable) {
            // diagnostics must never disturb the guest
        }
    }
}
