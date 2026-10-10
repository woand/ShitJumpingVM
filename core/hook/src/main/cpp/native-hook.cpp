/**
 * NEXTVM Native Hook Library
 *
 * PLT/GOT hooks for libc file I/O functions to implement native-level
 * path redirection for guest app file isolation.
 *
 * Hooks (installed via GOT patching):
 *   - open/openat     → redirect file paths to sandbox
 *   - access          → check sandbox path instead
 *   - stat/lstat      → stat sandbox path instead
 *   - readlink        → return sandbox path
 *   - fopen           → redirect file paths to sandbox
 *   - __system_property_get → spoof device properties
 *
 * Architecture:
 *   Java (NativeHookBridge.kt)
 *     ↓ JNI
 *   native-hook.cpp (this file)
 *     ↓ GOT/PLT patching via dl_iterate_phdr + ELF parsing
 *   hooked libc functions ←→ original libc functions (via saved pointers)
 */

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <dirent.h>

// Define ELF_R_SYM if not provided by NDK headers
#ifndef ELF_R_SYM
#ifdef __LP64__
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#endif
#endif

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <cerrno>
#include <signal.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <android/dlext.h>

#ifndef SYS_memfd_create
#  if defined(__aarch64__)
#    define SYS_memfd_create 279
#  elif defined(__arm__)
#    define SYS_memfd_create 385
#  elif defined(__x86_64__)
#    define SYS_memfd_create 319
#  endif
#endif

#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
#endif

#define LOG_TAG "NextVM-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== Global State ====================

static bool g_initialized = false;
static bool g_hooks_installed = false;
static std::mutex g_mutex;

// Path redirection: source prefix → target prefix
static std::unordered_map<std::string, std::string> g_path_redirects;

// Property spoofing: property name → spoofed value
static std::unordered_map<std::string, std::string> g_property_spoofs;

// Hidden paths: paths that should appear non-existent
static std::unordered_set<std::string> g_hidden_paths;

// /proc/self spoofing
static int g_spoofed_pid = -1;
static std::string g_spoofed_package_name;

// Host package data dir prefix
static std::string g_host_data_prefix;

// Virtual data root
static std::string g_virtual_data_root;

// ==================== Original Function Pointers ====================

typedef int (*orig_open_t)(const char*, int, ...);
typedef int (*orig_openat_t)(int, const char*, int, ...);
typedef int (*orig_access_t)(const char*, int);
typedef int (*orig_stat_t)(const char*, struct stat*);
typedef int (*orig_lstat_t)(const char*, struct stat*);
typedef ssize_t (*orig_readlink_t)(const char*, char*, size_t);
typedef FILE* (*orig_fopen_t)(const char*, const char*);
typedef int (*orig_system_property_get_t)(const char*, char*);

static orig_open_t real_open = nullptr;
static orig_openat_t real_openat = nullptr;
static orig_access_t real_access = nullptr;
static orig_stat_t real_stat = nullptr;
static orig_lstat_t real_lstat = nullptr;
static orig_readlink_t real_readlink = nullptr;
static orig_fopen_t real_fopen = nullptr;
static orig_system_property_get_t real_system_property_get = nullptr;

typedef void* (*orig_dlopen_t)(const char*, int);
typedef void* (*orig_android_dlopen_ext_t)(const char*, int, const android_dlextinfo*);

static orig_dlopen_t real_dlopen = nullptr;
static orig_android_dlopen_ext_t real_android_dlopen_ext = nullptr;

// Defined in the GOT/PLT section below: re-runs the patch pass so that
// libraries loaded after nativeInit (e.g. a packer shell's .so brought in
// via System.loadLibrary) receive the same GOT hooks as startup libraries.
static void patch_newly_loaded_libraries();

// ==================== Path Redirection Logic ====================

/**
 * Check if a path is hidden.
 */
static bool is_path_hidden(const char* path) {
    if (path == nullptr || g_hidden_paths.empty()) return false;
    return g_hidden_paths.count(std::string(path)) > 0;
}

/**
 * Check if a path needs redirection and return the redirected path.
 * Returns empty string if no redirection needed.
 */
static std::string redirect_path(const char* path) {
    if (path == nullptr || path[0] == '\0') return "";
    if (g_path_redirects.empty()) return "";

    std::string path_str(path);

    // Check each registered redirect prefix (longest match wins)
    std::string best_from;
    std::string best_to;
    for (const auto& redirect : g_path_redirects) {
        if (path_str.compare(0, redirect.first.length(), redirect.first) == 0) {
            if (redirect.first.length() > best_from.length()) {
                best_from = redirect.first;
                best_to = redirect.second;
            }
        }
    }

    if (!best_from.empty()) {
        return best_to + path_str.substr(best_from.length());
    }

    // Special case: /data/user/0/ is the same as /data/data/
    if (path_str.compare(0, 13, "/data/user/0/") == 0) {
        std::string alt_path = "/data/data/" + path_str.substr(13);
        return redirect_path(alt_path.c_str());
    }

    return "";
}

/**
 * Check if a path is a /proc/self path that needs spoofing.
 */
static bool is_proc_self_path(const char* path) {
    if (path == nullptr) return false;
    return strncmp(path, "/proc/self/", 11) == 0;
}

// ==================== Hook Implementations ====================

// ==================== /proc/self Spoof Content ====================

enum ProcSpoofKind {
    PROC_SPOOF_NONE = 0,
    PROC_SPOOF_CMDLINE,
    PROC_SPOOF_MAPS,
    PROC_SPOOF_COMM,
    PROC_SPOOF_STATUS,
    PROC_SPOOF_STAT
};

// Keywords that betray the virtual environment in /proc/self/maps.
// Shared by the fopen() and open()/openat() spoof paths.
static bool maps_line_visible(const char* line) {
    static const char* kHiddenKeywords[] = {
        "nextvm", "lsplant", "dobby", "bhook", "xhook", "substrate", "xposed"
    };
    for (const char* kw : kHiddenKeywords) {
        if (strstr(line, kw) != nullptr) return false;
    }
    return true;
}

// Synthetic "normal install" locations used to rewrite the guest's own
// mappings in /proc/self/maps. A stock device shows the guest APK under
// /data/app/~~<rand>==/<pkg>-<rand>==/base.apk with its extracted libs in
// the sibling lib/arm64 directory — mirror that shape (constant tokens
// are fine; what matters is that the paths stop betraying the virtual
// layout and stop containing the host's package name).
static std::string synthetic_apk_path() {
    return "/data/app/~~VmK8x2==/" + g_spoofed_package_name + "-VmK8x2==/base.apk";
}

static std::string synthetic_lib_path(const std::string& file_name) {
    return "/data/app/~~VmK8x2==/" + g_spoofed_package_name +
           "-VmK8x2==/lib/arm64/" + file_name;
}

/**
 * Rewrite a filesystem path that betrays the virtual layout into its
 * stock-install equivalent. Shared by the maps transform and by the
 * readlink result rewriting (fd symlink targets). Returns false when
 * the path needs no rewrite. When the path belongs to the host/engine
 * itself (no guest-side equivalent exists), *host_fallback is set and
 * `out` receives the synthetic APK path as a plausible stand-in —
 * callers that present listings (maps) should drop such entries
 * instead, callers that must return a path (readlink) use the stand-in.
 */
static bool rewrite_virtual_path(const std::string& path, std::string& out,
                                 bool* host_fallback = nullptr) {
    if (host_fallback != nullptr) *host_fallback = false;
    std::string core = path;
    std::string suffix;
    if (core.size() >= 11 &&
        core.compare(core.size() - 11, 11, " (deleted)") == 0) {
        core.erase(core.size() - 11);
        suffix = " (deleted)";
    }

    // Guest APK files: base + split APKs (virtual storage names splits
    // "<instanceId>_split_config.<...>.apk"; stock form is the plain
    // split file name next to base.apk).
    if (core.find("/files/virtual/apks/") != std::string::npos &&
        core.size() >= 4 && core.compare(core.size() - 4, 4, ".apk") == 0) {
        std::string fname = core.substr(core.find_last_of('/') + 1);
        size_t split_pos = fname.find("split_");
        if (fname.find("_split_") != std::string::npos &&
            split_pos != std::string::npos) {
            out = "/data/app/~~VmK8x2==/" + g_spoofed_package_name +
                  "-VmK8x2==/" + fname.substr(split_pos) + suffix;
        } else {
            out = synthetic_apk_path() + suffix;
        }
        return true;
    }

    // Guest data tree: extracted libs go to the synthetic lib dir,
    // everything else mirrors under /data/data/<pkg>/.
    const std::string data_marker = "/files/virtual/data/";
    size_t data_pos = core.find(data_marker);
    if (data_pos != std::string::npos) {
        size_t inst_end = core.find('/', data_pos + data_marker.size());
        if (inst_end != std::string::npos) {
            std::string rest = core.substr(inst_end + 1);
            if (rest.compare(0, 4, "lib/") == 0) {
                out = synthetic_lib_path(
                    rest.substr(rest.find_last_of('/') + 1)) + suffix;
            } else {
                out = "/data/data/" + g_spoofed_package_name + "/" + rest +
                      suffix;
            }
            return true;
        }
    }

    // Anything else naming the host app is the engine/host itself.
    if (core.find("nextvm") != std::string::npos) {
        if (host_fallback != nullptr) *host_fallback = true;
        out = synthetic_apk_path() + suffix;
        return true;
    }
    return false;
}

/**
 * Transform one /proc/self/maps line for the spoofed view.
 * Returns false if the line must be dropped; otherwise fills `out`.
 *
 * v1 of this spoof simply dropped every line mentioning the host —
 * including the guest's OWN apk/lib mappings (they live under the
 * host's data dir), so a shell locating itself or its APK in maps
 * found nothing at all. v2 rewrites the guest's own paths to a
 * plausible stock-install layout and only drops lines that belong to
 * the host app / hook engine itself.
 */
static bool transform_maps_line(const char* line, std::string& out) {
    const char* slash = strchr(line, '/');
    if (slash != nullptr) {
        std::string prefix(line, static_cast<size_t>(slash - line));
        std::string core(slash);
        while (!core.empty() && (core.back() == '\n' || core.back() == '\r')) {
            core.pop_back();
        }

        std::string rewritten;
        bool host_fallback = false;
        if (rewrite_virtual_path(core, rewritten, &host_fallback)) {
            // Host/engine mappings have no guest-side equivalent; a
            // stock process simply has no such lines — drop them.
            if (host_fallback) return false;
            out = prefix + rewritten + "\n";
            return true;
        }
    }

    // Hook-framework keywords anywhere in the line (also covers
    // [anon:...] mapping names) — drop.
    if (!maps_line_visible(line)) return false;

    out = line;
    return true;
}

static std::string build_spoofed_maps() {
    std::string result;
    int fd = real_open != nullptr ? real_open("/proc/self/maps", O_RDONLY) : -1;
    if (fd < 0) return result;
    FILE* in = fdopen(fd, "r");
    if (in == nullptr) {
        close(fd);
        return result;
    }
    char line[4096];
    while (fgets(line, sizeof(line), in)) {
        std::string out;
        if (transform_maps_line(line, out)) result += out;
    }
    fclose(in);
    return result;
}

/**
 * Build the spoofed /proc/self/status: the real content with only the
 * Name line replaced. In a guest process Name reads "m.nextvm.app:p0";
 * replace it with the guest's comm (package truncated to 15 chars,
 * consistent with the comm spoof). Uid and TracerPid are kept real so
 * the content stays consistent with getuid() and with the actual
 * (untraced) state — the Java layer's fabricated Uid is NOT reused.
 */
static std::string read_whole_file(const char* path) {
    std::string content;
    int fd = real_open != nullptr ? real_open(path, O_RDONLY) : -1;
    if (fd < 0) return content;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return content;
}

static std::string build_spoofed_status(const char* src_path = nullptr) {
    std::string content = read_whole_file(
        src_path != nullptr ? src_path : "/proc/self/status");

    size_t pos = std::string::npos;
    if (content.compare(0, 6, "Name:\t") == 0) {
        pos = 0;
    } else {
        size_t p = content.find("\nName:\t");
        if (p != std::string::npos) pos = p + 1;
    }
    if (pos != std::string::npos) {
        size_t line_end = content.find('\n', pos);
        std::string name_line = "Name:\t" + g_spoofed_package_name.substr(0, 15);
        if (line_end == std::string::npos) {
            content = content.substr(0, pos) + name_line + "\n";
        } else {
            content = content.substr(0, pos) + name_line + content.substr(line_end);
        }
    }
    return content;
}

/**
 * Build the spoofed /proc/<pid>/stat (also serves task/<main-tid>/stat):
 * the real content with the parenthesised comm field replaced by the
 * guest's comm. Every other field (pid, timings, sizes) stays real.
 */
static std::string build_spoofed_stat(const char* src_path = nullptr) {
    std::string content = read_whole_file(
        src_path != nullptr ? src_path : "/proc/self/stat");
    size_t open = content.find('(');
    size_t close = content.rfind(')');
    if (open != std::string::npos && close != std::string::npos && close > open) {
        content = content.substr(0, open + 1) +
                  g_spoofed_package_name.substr(0, 15) +
                  content.substr(close);
    }
    return content;
}

/**
 * Classify a path as a spoofable /proc file (cmdline/maps/comm) for this
 * process — matches both /proc/self/<file> and /proc/<own-pid>/<file>.
 * Returns PROC_SPOOF_NONE when no spoofing applies (including when the
 * Java side never armed spoofing via nativeSpoofProcSelf).
 */
static ProcSpoofKind match_proc_spoof(const char* path) {
    if (path == nullptr || g_spoofed_package_name.empty()) return PROC_SPOOF_NONE;

    const char* base = nullptr;
    long owner_pid = -1;  // pid the requested file describes
    if (strncmp(path, "/proc/self/", 11) == 0) {
        base = path + 11;
        owner_pid = static_cast<long>(getpid());
    } else if (strncmp(path, "/proc/", 6) == 0) {
        char* end = nullptr;
        long pid = strtol(path + 6, &end, 10);
        if (end != nullptr && *end == '/') {
            // Own pid — or the armed guest process's pid, which is what
            // a forked child of the guest reads when it inspects its
            // parent (dual-process checks). The stub's own parent (the
            // zygote) deliberately does NOT match in the armed process
            // itself, because there owner references use getpid().
            if (pid == static_cast<long>(getpid()) ||
                pid == static_cast<long>(g_spoofed_pid)) {
                base = end + 1;
                owner_pid = pid;
            }
        }
    }
    if (base == nullptr) return PROC_SPOOF_NONE;

    if (strcmp(base, "cmdline") == 0) return PROC_SPOOF_CMDLINE;
    if (strcmp(base, "maps") == 0) return PROC_SPOOF_MAPS;
    if (strcmp(base, "comm") == 0) return PROC_SPOOF_COMM;
    if (strcmp(base, "status") == 0) return PROC_SPOOF_STATUS;
    if (strcmp(base, "stat") == 0) return PROC_SPOOF_STAT;

    // /proc/<pid>/task/<tid>/<file>: threads share the process cmdline,
    // so that leaf spoofs for every tid. comm/status/stat only betray
    // the guest for the MAIN thread (tid == pid), whose name is the
    // stub's "m.nextvm.app:pN"; the other threads carry generic ART
    // names identical to a stock app process and pass through real.
    if (strncmp(base, "task/", 5) == 0) {
        char* end = nullptr;
        long tid = strtol(base + 5, &end, 10);
        if (end != nullptr && *end == '/') {
            const char* leaf = end + 1;
            if (strcmp(leaf, "cmdline") == 0) return PROC_SPOOF_CMDLINE;
            if (tid == owner_pid) {
                if (strcmp(leaf, "comm") == 0) return PROC_SPOOF_COMM;
                if (strcmp(leaf, "status") == 0) return PROC_SPOOF_STATUS;
                if (strcmp(leaf, "stat") == 0) return PROC_SPOOF_STAT;
            }
        }
    }
    return PROC_SPOOF_NONE;
}

static bool write_all_fd(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

/**
 * Create an anonymous in-memory fd pre-filled with the spoofed content
 * for the given /proc file, positioned at offset 0. Falls back to a
 * tmpfile when memfd is unavailable. Returns -1 on failure.
 */
static int make_proc_spoof_fd(ProcSpoofKind kind, const char* src_path = nullptr) {
    int fd = -1;
#ifdef SYS_memfd_create
    fd = static_cast<int>(syscall(SYS_memfd_create, "proc", MFD_CLOEXEC));
#endif
    FILE* tmp = nullptr;
    if (fd < 0) {
        tmp = tmpfile();
        if (tmp == nullptr) return -1;
        fd = fileno(tmp);
    }

    bool ok = true;
    if (kind == PROC_SPOOF_CMDLINE) {
        ok = write_all_fd(fd, g_spoofed_package_name.c_str(),
                          g_spoofed_package_name.length() + 1);
    } else if (kind == PROC_SPOOF_COMM) {
        std::string comm = g_spoofed_package_name.substr(0, 15) + "\n";
        ok = write_all_fd(fd, comm.c_str(), comm.length());
    } else if (kind == PROC_SPOOF_MAPS) {
        std::string content = build_spoofed_maps();
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    } else if (kind == PROC_SPOOF_STATUS) {
        std::string content = build_spoofed_status(src_path);
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    } else if (kind == PROC_SPOOF_STAT) {
        std::string content = build_spoofed_stat(src_path);
        ok = !content.empty() && write_all_fd(fd, content.data(), content.size());
    }

    if (!ok) {
        if (tmp != nullptr) fclose(tmp); else close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    if (tmp != nullptr) {
        // dup so the caller owns an fd independent of the tmpfile's FILE;
        // the shared offset was just rewound to 0.
        int out = dup(fd);
        fclose(tmp);
        fd = out;
    }

    if (fd >= 0) {
        static int logged_cmdline = 0, logged_maps = 0, logged_comm = 0, logged_status = 0, logged_stat = 0;
        int* counter = &logged_cmdline;
        const char* name = "cmdline";
        if (kind == PROC_SPOOF_MAPS) { counter = &logged_maps; name = "maps"; }
        else if (kind == PROC_SPOOF_COMM) { counter = &logged_comm; name = "comm"; }
        else if (kind == PROC_SPOOF_STATUS) { counter = &logged_status; name = "status"; }
        else if (kind == PROC_SPOOF_STAT) { counter = &logged_stat; name = "stat"; }
        if (*counter < 3) {
            (*counter)++;
            LOGI("open: served spoofed /proc/self/%s (pkg=%s)", name,
                 g_spoofed_package_name.c_str());
        }
    }
    return fd;
}

/**
 * Hooked open() — redirects file paths to sandbox, hides paths.
 */
static int hooked_open(const char* path, int flags, ...) {
    // Check hidden paths
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Serve spoofed /proc/self files — packer shells read cmdline/maps
    // via open() during their environment checks, long before any Java
    // code runs. Only fopen() was spoofed previously, which native code
    // rarely uses.
    if ((flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind != PROC_SPOOF_NONE) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) return fd;
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("open: %s -> %s", path, actual_path);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
        return real_open(actual_path, flags, mode);
    }
    return real_open(actual_path, flags);
}

/**
 * Hooked openat() — redirects file paths to sandbox, hides paths.
 */
static int hooked_openat(int dirfd, const char* path, int flags, ...) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Serve spoofed /proc/self files for absolute paths (dirfd is
    // ignored for absolute paths by the kernel anyway).
    if (path != nullptr && path[0] == '/' && (flags & O_ACCMODE) == O_RDONLY) {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind != PROC_SPOOF_NONE) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) return fd;
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("openat: %s -> %s", path, actual_path);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
        return real_openat(dirfd, actual_path, flags, mode);
    }
    return real_openat(dirfd, actual_path, flags);
}

/**
 * Hooked access() — checks sandbox path instead, hides paths.
 */
static int hooked_access(const char* path, int mode) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_access(actual_path, mode);
}

/**
 * Hooked stat() — stats sandbox path instead, hides paths.
 */
static int hooked_stat(const char* path, struct stat* buf) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_stat(actual_path, buf);
}

/**
 * Hooked lstat() — lstats sandbox path instead, hides paths.
 */
static int hooked_lstat(const char* path, struct stat* buf) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    return real_lstat(actual_path, buf);
}

/**
 * Hooked readlink() — returns sandbox path instead.
 */
static ssize_t hooked_readlink(const char* path, char* buf, size_t bufsiz) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    // Spoof /proc/self/exe
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/exe") == 0 &&
        !g_spoofed_package_name.empty()) {
        // Return a fake exe path
        std::string fake = "/system/bin/app_process64";
        size_t len = fake.length();
        if (len > bufsiz) len = bufsiz;
        memcpy(buf, fake.c_str(), len);
        return static_cast<ssize_t>(len);
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    ssize_t n = real_readlink(actual_path, buf, bufsiz);
    // When spoofing is armed, rewrite the RESULT if it names a virtual
    // path. Directory enumerators learn the world from readlink targets
    // (above all the /proc/*/fd symlink walk a packer shell performs),
    // not from the paths passed in — fd targets must not leak the host
    // layout, other guests' identities, or the word "virtual".
    if (n > 0 && !g_spoofed_package_name.empty()) {
        std::string target(buf, static_cast<size_t>(n));
        std::string rewritten;
        if (rewrite_virtual_path(target, rewritten)) {
            size_t len = rewritten.length();
            if (len > bufsiz) len = bufsiz;
            memcpy(buf, rewritten.c_str(), len);
            static int logged = 0;
            if (logged < 5) {
                logged++;
                LOGI("readlink: rewrote target %s -> %s",
                     target.c_str(), rewritten.c_str());
            }
            return static_cast<ssize_t>(len);
        }
    }
    return n;
}

/**
 * Hooked fopen() — redirects file paths to sandbox, hides paths.
 */
static FILE* hooked_fopen(const char* path, const char* mode) {
    if (is_path_hidden(path)) {
        errno = ENOENT;
        return nullptr;
    }

    // Spoof /proc/<pid>/stat and /proc/<pid>/task/<tid>/{cmdline,comm,
    // status,stat} through the shared matcher — the per-file branches
    // below only cover the top-level /proc/self forms.
    {
        ProcSpoofKind kind = match_proc_spoof(path);
        if (kind == PROC_SPOOF_STAT ||
            (kind != PROC_SPOOF_NONE && strstr(path, "/task/") != nullptr)) {
            int fd = make_proc_spoof_fd(kind, path);
            if (fd >= 0) {
                FILE* f = fdopen(fd, mode != nullptr ? mode : "r");
                if (f != nullptr) return f;
                close(fd);
            }
        }
    }

    // Spoof /proc/self/cmdline
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/cmdline") == 0 &&
        !g_spoofed_package_name.empty()) {
        // Create a temp file with spoofed cmdline
        FILE* tmp = tmpfile();
        if (tmp) {
            fwrite(g_spoofed_package_name.c_str(), 1, g_spoofed_package_name.length() + 1, tmp);
            fseek(tmp, 0, SEEK_SET);
            return tmp;
        }
    }

    // Spoof /proc/self/comm
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/comm") == 0 &&
        !g_spoofed_package_name.empty()) {
        FILE* tmp = tmpfile();
        if (tmp) {
            std::string comm = g_spoofed_package_name.substr(0, 15) + "\n";
            fwrite(comm.c_str(), 1, comm.length(), tmp);
            fseek(tmp, 0, SEEK_SET);
            return tmp;
        }
    }

    // Spoof /proc/self/maps — guest paths rewritten to a stock-install
    // layout, host/engine lines dropped (shared with the open() path)
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/maps") == 0 &&
        !g_spoofed_package_name.empty()) {
        std::string content = build_spoofed_maps();
        if (!content.empty()) {
            FILE* tmp = tmpfile();
            if (tmp) {
                fwrite(content.data(), 1, content.size(), tmp);
                fseek(tmp, 0, SEEK_SET);
                return tmp;
            }
        }
    }

    // Spoof /proc/self/status — real content, Name line replaced
    if (is_proc_self_path(path) && strcmp(path, "/proc/self/status") == 0 &&
        !g_spoofed_package_name.empty()) {
        std::string content = build_spoofed_status();
        if (!content.empty()) {
            FILE* tmp = tmpfile();
            if (tmp) {
                fwrite(content.data(), 1, content.size(), tmp);
                fseek(tmp, 0, SEEK_SET);
                return tmp;
            }
        }
    }

    std::string redirected = redirect_path(path);
    const char* actual_path = redirected.empty() ? path : redirected.c_str();

    if (!redirected.empty()) {
        LOGD("fopen: %s -> %s", path, actual_path);
    }

    return real_fopen(actual_path, mode);
}

/**
 * Hooked __system_property_get() — returns spoofed device properties.
 */
static int hooked_system_property_get(const char* name, char* value) {
    // Check if we have a spoofed value for this property
    if (name != nullptr && !g_property_spoofs.empty()) {
        std::string prop_name(name);
        auto it = g_property_spoofs.find(prop_name);
        if (it != g_property_spoofs.end()) {
            const std::string& spoofed = it->second;
            size_t len = spoofed.length();
            if (len > 91) len = 91; // PROP_VALUE_MAX - 1
            memcpy(value, spoofed.c_str(), len);
            value[len] = '\0';
            LOGD("property_get: %s -> %s (spoofed)", name, value);
            return static_cast<int>(len);
        }
    }

    // No spoof — call real implementation
    return real_system_property_get(name, value);
}

/**
 * Hooked dlopen() — after a successful load, patch the GOTs of any
 * libraries that just arrived. Packer shells (e.g. SecNeo's
 * libDexHelper.so) are dlopen'd by the guest Application long after
 * nativeInit's one-shot patch pass; without this, none of the hooks —
 * including the /proc/self spoofing — apply to the shell's own calls.
 */
static void* hooked_dlopen(const char* filename, int flags) {
    void* handle = real_dlopen != nullptr ? real_dlopen(filename, flags) : nullptr;
    if (handle != nullptr) {
        patch_newly_loaded_libraries();
    }
    return handle;
}

/**
 * Hooked android_dlopen_ext() — same late-patch behavior as dlopen.
 * This is the entry point the native loader itself uses for
 * namespaced library loads (System.loadLibrary).
 */
static void* hooked_android_dlopen_ext(const char* filename, int flags,
                                       const android_dlextinfo* extinfo) {
    void* handle = real_android_dlopen_ext != nullptr
        ? real_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (handle != nullptr) {
        patch_newly_loaded_libraries();
    }
    return handle;
}

// ==================== Diagnostic hooks (log-only) ====================
//
// Identify which environment channel a packer shell actually uses
// before dying: dl_iterate_phdr (library enumeration that bypasses all
// /proc spoofing), ptrace + fork (dual-process anti-debug dance),
// syscall (raw syscalls that bypass the PLT hooks on open/openat), and
// opendir (directory enumeration; its libc-internal openat also
// bypasses our PLT hooks). These hooks NEVER alter behaviour: they log
// (rate limited, caller attributed via dladdr) and forward to the real
// implementation.

typedef int (*orig_dl_iterate_phdr_t)(int (*)(struct dl_phdr_info*, size_t, void*), void*);
typedef long (*orig_ptrace_t)(int, ...);
typedef long (*orig_syscall_t)(long, ...);
typedef pid_t (*orig_fork_t)();
typedef DIR* (*orig_opendir_t)(const char*);

static orig_dl_iterate_phdr_t real_dl_iterate_phdr = nullptr;
static orig_ptrace_t real_ptrace = nullptr;
static orig_syscall_t real_syscall = nullptr;
static orig_fork_t real_fork = nullptr;
static orig_opendir_t real_opendir = nullptr;

static void diag_caller(void* ret_addr, char* buf, size_t len) {
    Dl_info info;
    if (ret_addr != nullptr && dladdr(ret_addr, &info) && info.dli_fname != nullptr) {
        const char* base = strrchr(info.dli_fname, '/');
        snprintf(buf, len, "%s", base != nullptr ? base + 1 : info.dli_fname);
    } else {
        snprintf(buf, len, "?");
    }
}

static int hooked_dl_iterate_phdr(int (*callback)(struct dl_phdr_info*, size_t, void*),
                                  void* data) {
    static int logged = 0;
    if (logged < 10) {
        logged++;
        char who[128], cb_who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        diag_caller((void*)callback, cb_who, sizeof(cb_who));
        LOGI("DIAG dl_iterate_phdr called by %s (callback in %s)", who, cb_who);
    }
    if (real_dl_iterate_phdr) return real_dl_iterate_phdr(callback, data);
    return -1;
}

static long hooked_ptrace(int request, ...) {
    va_list ap;
    va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void* addr = va_arg(ap, void*);
    void* data = va_arg(ap, void*);
    va_end(ap);
    static int logged = 0;
    if (logged < 30) {
        logged++;
        char who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        LOGI("DIAG ptrace req=%d pid=%d addr=%p data=%p by %s",
             request, (int)pid, addr, data, who);
    }
    if (real_ptrace) return real_ptrace(request, pid, addr, data);
    errno = ENOSYS;
    return -1;
}

static long hooked_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    static __thread bool in_hook = false;
    if (!in_hook) {
        in_hook = true;
        // aarch64 numbers of interest: faccessat=48, openat=56, close=57,
        // getdents64=61, read=63, pread64=67, readlinkat=78,
        // newfstatat=79, ptrace=117, kill=129, tgkill=131, clone=220
        bool interesting = number == 48 || number == 56 || number == 57 ||
                           number == 61 || number == 63 || number == 67 ||
                           number == 78 || number == 79 || number == 117 ||
                           number == 129 || number == 131 || number == 220;
        static int logged_int = 0, logged_other = 0;
        if ((interesting && logged_int < 40) || (!interesting && logged_other < 10)) {
            if (interesting) logged_int++; else logged_other++;
            char who[128];
            diag_caller(__builtin_return_address(0), who, sizeof(who));
            if (number == 56 && a2 != 0) {
                LOGI("DIAG syscall openat dirfd=%ld path=%s by %s",
                     a1, (const char*)a2, who);
            } else {
                LOGI("DIAG syscall nr=%ld a1=%ld a2=%ld a3=%ld by %s",
                     number, a1, a2, a3, who);
            }
        }
        in_hook = false;
    }
    if (real_syscall) return real_syscall(number, a1, a2, a3, a4, a5, a6);
    errno = ENOSYS;
    return -1;
}

static pid_t hooked_fork() {
    static int logged = 0;
    bool log_it = logged < 10;
    if (log_it) {
        logged++;
        char who[128];
        diag_caller(__builtin_return_address(0), who, sizeof(who));
        LOGI("DIAG fork called by %s (in pid %d)", who, (int)getpid());
    }
    pid_t r = real_fork ? real_fork() : -1;
    if (log_it) LOGI("DIAG fork returned %d in pid %d", (int)r, (int)getpid());
    return r;
}

static DIR* hooked_opendir(const char* path) {
    if (path != nullptr && strstr(path, "/proc") != nullptr) {
        static int logged = 0;
        if (logged < 20) {
            logged++;
            char who[128];
            diag_caller(__builtin_return_address(0), who, sizeof(who));
            LOGI("DIAG opendir %s by %s", path, who);
        }
    }
    if (real_opendir) return real_opendir(path);
    return nullptr;
}

// ==================== GOT/PLT Hook Installation ====================

// SIGSEGV-safe memory probe: returns false if the address is not readable
static thread_local sigjmp_buf g_probe_jmp;
static thread_local volatile bool g_probing = false;

static void probe_signal_handler(int sig) {
    if (g_probing) {
        siglongjmp(g_probe_jmp, 1);
    }
}

/**
 * Check if a memory address is safely readable using mincore() as a fast check,
 * falling back to a SIGSEGV-safe read probe.
 */
static bool is_address_readable(const void* addr, size_t len) {
    if (addr == nullptr) return false;
    uintptr_t uaddr = reinterpret_cast<uintptr_t>(addr);
    // Reject addresses in the first 64KB (likely relative offsets, not real pointers)
    if (uaddr < 0x10000) return false;

    // Try writing to /proc/self/mem trick — but simplest: use msync as a probe
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t page_start = uaddr & ~(page_size - 1);
    // msync on a non-mapped page returns -1 with ENOMEM
    if (msync(reinterpret_cast<void*>(page_start), page_size, MS_ASYNC) != 0) {
        return false;
    }
    // Also check the end of the range
    uintptr_t end_page = (uaddr + len - 1) & ~(page_size - 1);
    if (end_page != page_start) {
        if (msync(reinterpret_cast<void*>(end_page), page_size, MS_ASYNC) != 0) {
            return false;
        }
    }
    return true;
}

/**
 * Hook entry: maps a symbol name to our hook function and the saved original pointer.
 */
struct HookEntry {
    const char* symbol;
    void* hook_func;
    void** original_func;
};

static HookEntry g_hook_entries[] = {
    {"open",                    (void*)hooked_open,                 (void**)&real_open},
    {"openat",                  (void*)hooked_openat,               (void**)&real_openat},
    {"access",                  (void*)hooked_access,               (void**)&real_access},
    {"stat",                    (void*)hooked_stat,                 (void**)&real_stat},
    {"lstat",                   (void*)hooked_lstat,                (void**)&real_lstat},
    {"readlink",                (void*)hooked_readlink,             (void**)&real_readlink},
    {"fopen",                   (void*)hooked_fopen,                (void**)&real_fopen},
    {"__system_property_get",   (void*)hooked_system_property_get,  (void**)&real_system_property_get},
    {"open64",                  (void*)hooked_open,                 (void**)&real_open},
    {"openat64",                (void*)hooked_openat,               (void**)&real_openat},
    {"fopen64",                 (void*)hooked_fopen,                (void**)&real_fopen},
    {"dlopen",                  (void*)hooked_dlopen,               (void**)&real_dlopen},
    {"android_dlopen_ext",      (void*)hooked_android_dlopen_ext,   (void**)&real_android_dlopen_ext},
    {"dl_iterate_phdr",         (void*)hooked_dl_iterate_phdr,      (void**)&real_dl_iterate_phdr},
    {"ptrace",                  (void*)hooked_ptrace,               (void**)&real_ptrace},
    {"syscall",                 (void*)hooked_syscall,              (void**)&real_syscall},
    {"fork",                    (void*)hooked_fork,                 (void**)&real_fork},
    {"opendir",                 (void*)hooked_opendir,              (void**)&real_opendir},
};
static constexpr int g_hook_count = sizeof(g_hook_entries) / sizeof(g_hook_entries[0]);

/**
 * Replace a single GOT entry.
 * Makes the GOT page writable, swaps the pointer, restores permissions.
 *
 * @param got_addr  Pointer to the GOT entry to patch
 * @param new_func  The hook function to install
 * @param old_func  Output: the original function pointer that was in the GOT
 * @return true on success
 */
static bool patch_got_entry(void** got_addr, void* new_func, void** old_func) {
    if (got_addr == nullptr) return false;
    // Validate the GOT address is in readable memory before dereferencing
    if (!is_address_readable(got_addr, sizeof(void*))) {
        LOGW("GOT addr %p not readable, skipping", got_addr);
        return false;
    }
    if (*got_addr == nullptr) return false;

    // Don't patch if already pointing to our hook
    if (*got_addr == new_func) return true;

    // Save the original
    if (old_func && *old_func == nullptr) {
        *old_func = *got_addr;
    }

    // Calculate page-aligned address
    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t page_start = reinterpret_cast<uintptr_t>(got_addr) & ~(page_size - 1);

    // Make page writable
    if (mprotect(reinterpret_cast<void*>(page_start), page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect RW failed for GOT entry at %p: %s",
             got_addr, strerror(errno));
        return false;
    }

    // Patch the GOT entry
    *got_addr = new_func;

    // Restore page permissions (read-only)
    mprotect(reinterpret_cast<void*>(page_start), page_size, PROT_READ);

    return true;
}

/**
 * Process a single loaded shared object: find its GOT and patch entries.
 *
 * Parses the ELF dynamic section to locate .rel.plt / .rela.plt relocations,
 * then patches GOT entries for our target symbols.
 */
static void patch_library_got(uintptr_t base_addr, const char* lib_name,
                               const ElfW(Dyn)* dynamic) {
    if (dynamic == nullptr) return;

    // Find required dynamic entries
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const ElfW(Rel)* rel_plt = nullptr;
    const ElfW(Rela)* rela_plt = nullptr;
    size_t rel_plt_size = 0;
    size_t rela_plt_size = 0;
    bool use_rela = false;

    for (const ElfW(Dyn)* dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = reinterpret_cast<const ElfW(Sym)*>(dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(dyn->d_un.d_ptr);
                break;
            case DT_JMPREL:
                // Could be REL or RELA depending on DT_PLTREL
                rel_plt = reinterpret_cast<const ElfW(Rel)*>(dyn->d_un.d_ptr);
                rela_plt = reinterpret_cast<const ElfW(Rela)*>(dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                rel_plt_size = dyn->d_un.d_val;
                rela_plt_size = dyn->d_un.d_val;
                break;
            case DT_PLTREL:
                use_rela = (dyn->d_un.d_val == DT_RELA);
                break;
        }
    }

    if (symtab == nullptr || strtab == nullptr) return;
    if (rel_plt == nullptr && rela_plt == nullptr) return;

    // Normalize dynamic-segment pointers. On Android 17 many libraries keep
    // link-time virtual addresses (offsets relative to the load bias) in their
    // in-memory PT_DYNAMIC entries instead of relocated absolute addresses.
    // Any d_ptr below base_addr is such an offset and must be rebased by the
    // load bias; pointers at/above base_addr are already absolute and are left
    // untouched. The previous code only rebased symtab/strtab when they were
    // below 0x10000 — real offsets are routinely larger than that (e.g.
    // strtab=0x23250), and rela_plt/rel_plt were never rebased at all — so
    // essentially every library failed the readability probes below and was
    // skipped (observed: 354 skipped, 0 hooked on Android 17 / SDK 37).
    if (base_addr == 0) {
        LOGW("Skipping %s: base_addr=0, cannot rebase dynamic pointers", lib_name);
        return;
    }
    auto rebase_ptr = [base_addr](uintptr_t p) -> uintptr_t {
        return (p != 0 && p < base_addr) ? base_addr + p : p;
    };
    symtab = reinterpret_cast<const ElfW(Sym)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(symtab)));
    strtab = reinterpret_cast<const char*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(strtab)));
    rel_plt = reinterpret_cast<const ElfW(Rel)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(rel_plt)));
    rela_plt = reinterpret_cast<const ElfW(Rela)*>(
        rebase_ptr(reinterpret_cast<uintptr_t>(rela_plt)));

    // Verify symtab and strtab are actually readable memory
    if (!is_address_readable(symtab, sizeof(ElfW(Sym))) ||
        !is_address_readable(strtab, 1)) {
        LOGW("Skipping %s: symtab(%p) or strtab(%p) not in readable memory",
             lib_name, symtab, strtab);
        return;
    }

    // Also validate relocation table pointer
    if (use_rela && rela_plt) {
        if (!is_address_readable(rela_plt, sizeof(ElfW(Rela)))) {
            LOGW("Skipping %s: rela_plt(%p) not readable", lib_name, rela_plt);
            return;
        }
    } else if (rel_plt) {
        if (!is_address_readable(rel_plt, sizeof(ElfW(Rel)))) {
            LOGW("Skipping %s: rel_plt(%p) not readable", lib_name, rel_plt);
            return;
        }
    }

    if (use_rela && rela_plt != nullptr && rela_plt_size > 0) {
        // Process RELA entries (arm64, x86_64)
        size_t count = rela_plt_size / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rela)& entry = rela_plt[i];
            size_t sym_idx = ELF_R_SYM(entry.r_info);
            if (sym_idx == 0) continue;

            // Validate sym_idx access is safe
            const ElfW(Sym)* sym_entry_ptr = &symtab[sym_idx];
            if (!is_address_readable(sym_entry_ptr, sizeof(ElfW(Sym)))) continue;

            uint32_t st_name = symtab[sym_idx].st_name;
            const char* sym_name = strtab + st_name;
            if (!is_address_readable(sym_name, 1)) continue;
            if (sym_name[0] == '\0') continue;

            // Check if this symbol is one we want to hook
            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hook_entries[h].symbol) == 0) {
                    void** got_addr = reinterpret_cast<void**>(
                        base_addr + entry.r_offset);
                    if (patch_got_entry(got_addr, g_hook_entries[h].hook_func,
                                       g_hook_entries[h].original_func)) {
                        LOGD("Hooked %s in %s (RELA)", sym_name, lib_name);
                    }
                    break;
                }
            }
        }
    } else if (rel_plt != nullptr && rel_plt_size > 0) {
        // Process REL entries (arm32, x86)
        size_t count = rel_plt_size / sizeof(ElfW(Rel));
        for (size_t i = 0; i < count; i++) {
            const ElfW(Rel)& entry = rel_plt[i];
            size_t sym_idx = ELF_R_SYM(entry.r_info);
            if (sym_idx == 0) continue;

            // Validate sym_idx access is safe
            const ElfW(Sym)* sym_entry_ptr = &symtab[sym_idx];
            if (!is_address_readable(sym_entry_ptr, sizeof(ElfW(Sym)))) continue;

            uint32_t st_name = symtab[sym_idx].st_name;
            const char* sym_name = strtab + st_name;
            if (!is_address_readable(sym_name, 1)) continue;
            if (sym_name[0] == '\0') continue;

            for (int h = 0; h < g_hook_count; h++) {
                if (strcmp(sym_name, g_hook_entries[h].symbol) == 0) {
                    void** got_addr = reinterpret_cast<void**>(
                        base_addr + entry.r_offset);
                    if (patch_got_entry(got_addr, g_hook_entries[h].hook_func,
                                       g_hook_entries[h].original_func)) {
                        LOGD("Hooked %s in %s (REL)", sym_name, lib_name);
                    }
                    break;
                }
            }
        }
    }
}

// Base addresses already processed by a patch pass. Libraries loaded
// after nativeInit are patched by re-running the pass from the dlopen
// hooks; this set keeps the pass idempotent and cheap.
static std::unordered_set<uintptr_t> g_patched_bases;
static std::mutex g_patch_mutex;

/**
 * dl_iterate_phdr callback — called for each loaded shared object.
 * We find the PT_DYNAMIC segment and use it to locate GOT entries.
 */
static int install_hooks_callback(struct dl_phdr_info* info, size_t /*size*/, void* /*data*/) {
    if (info->dlpi_name == nullptr) return 0;

    // Already processed by an earlier pass — nothing to do.
    if (info->dlpi_addr != 0 && g_patched_bases.count(info->dlpi_addr)) return 0;

    const char* name = info->dlpi_name;

    // Skip empty names (main executable) and our own library
    if (name[0] == '\0') return 0;
    if (strstr(name, "libnextvm") != nullptr) return 0;

    // Skip the linker itself
    if (strstr(name, "linker") != nullptr) return 0;

    // Skip vDSO and other kernel-mapped objects (no valid GOT to patch)
    if (strstr(name, "vdso") != nullptr) return 0;
    if (strstr(name, "[vdso]") != nullptr) return 0;

    // Skip libraries that commonly have RELRO-protected GOTs causing issues
    if (strstr(name, "libart.so") != nullptr) return 0;
    if (strstr(name, "libhwbinder") != nullptr) return 0;

    // Find PT_DYNAMIC segment
    const ElfW(Dyn)* dynamic = nullptr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<const ElfW(Dyn)*>(
                info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (dynamic != nullptr) {
        patch_library_got(info->dlpi_addr, name, dynamic);
    }

    if (info->dlpi_addr != 0) g_patched_bases.insert(info->dlpi_addr);

    return 0;
}

/**
 * Install GOT/PLT hooks into all currently loaded shared objects.
 */
static bool install_plt_hooks() {
    LOGI("Installing PLT hooks via GOT patching...");

    // Resolve original function pointers first (before hooking)
    if (!real_open)
        real_open = (orig_open_t)dlsym(RTLD_DEFAULT, "open");
    if (!real_openat)
        real_openat = (orig_openat_t)dlsym(RTLD_DEFAULT, "openat");
    if (!real_access)
        real_access = (orig_access_t)dlsym(RTLD_DEFAULT, "access");
    if (!real_stat)
        real_stat = (orig_stat_t)dlsym(RTLD_DEFAULT, "stat");
    if (!real_lstat)
        real_lstat = (orig_lstat_t)dlsym(RTLD_DEFAULT, "lstat");
    if (!real_readlink)
        real_readlink = (orig_readlink_t)dlsym(RTLD_DEFAULT, "readlink");
    if (!real_fopen)
        real_fopen = (orig_fopen_t)dlsym(RTLD_DEFAULT, "fopen");
    if (!real_system_property_get)
        real_system_property_get = (orig_system_property_get_t)dlsym(
            RTLD_DEFAULT, "__system_property_get");
    if (!real_dlopen)
        real_dlopen = (orig_dlopen_t)dlsym(RTLD_DEFAULT, "dlopen");
    if (!real_android_dlopen_ext)
        real_android_dlopen_ext = (orig_android_dlopen_ext_t)dlsym(
            RTLD_DEFAULT, "android_dlopen_ext");
    if (!real_dl_iterate_phdr)
        real_dl_iterate_phdr = (orig_dl_iterate_phdr_t)dlsym(
            RTLD_DEFAULT, "dl_iterate_phdr");
    if (!real_ptrace)
        real_ptrace = (orig_ptrace_t)dlsym(RTLD_DEFAULT, "ptrace");
    if (!real_syscall)
        real_syscall = (orig_syscall_t)dlsym(RTLD_DEFAULT, "syscall");
    if (!real_fork)
        real_fork = (orig_fork_t)dlsym(RTLD_DEFAULT, "fork");
    if (!real_opendir)
        real_opendir = (orig_opendir_t)dlsym(RTLD_DEFAULT, "opendir");

    if (!real_open || !real_openat || !real_access || !real_stat) {
        LOGE("Failed to resolve one or more libc functions via dlsym");
        return false;
    }

    // Iterate all loaded libraries and patch GOT entries
    {
        std::lock_guard<std::mutex> lock(g_patch_mutex);
        dl_iterate_phdr(install_hooks_callback, nullptr);
    }

    LOGI("PLT hooks installed successfully");
    return true;
}

// Seccomp raw-syscall diagnostic: forward declaration (impl below).
// Refreshed after every late-patch pass so libraries loaded by the
// guest (e.g. a packer's .so) become attributable in the trap log.
static void sc_refresh_modules();

/**
 * Re-run the GOT patch pass so libraries loaded after nativeInit
 * (via dlopen / android_dlopen_ext / Runtime.nativeLoad) receive the
 * same hooks as startup libraries. Idempotent: libraries already
 * processed are skipped via g_patched_bases.
 */
static void patch_newly_loaded_libraries() {
    static thread_local bool in_pass = false;
    if (in_pass || !g_initialized) return;
    in_pass = true;

    size_t added = 0;
    {
        std::lock_guard<std::mutex> lock(g_patch_mutex);
        size_t before = g_patched_bases.size();
        dl_iterate_phdr(install_hooks_callback, nullptr);
        added = g_patched_bases.size() - before;
    }
    if (added > 0) {
        LOGI("Late-patch: GOT hooks applied to %zu newly loaded librar%s",
             added, added == 1 ? "y" : "ies");
    }

    sc_refresh_modules();
    in_pass = false;
}

// ==================== JNI Bridge ====================

extern "C" {

/**
 * Initialize the native hook engine.
 * Resolves original function pointers and installs GOT/PLT hooks.
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeInit(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_initialized) {
        LOGI("Native hook engine already initialized");
        return JNI_TRUE;
    }

    LOGI("Initializing NEXTVM native hook engine...");

    // Install PLT hooks via GOT patching
    g_hooks_installed = install_plt_hooks();
    if (!g_hooks_installed) {
        LOGW("GOT/PLT hooking failed — falling back to Java-level hooks only");
    }

    g_initialized = true;
    LOGI("Native hook engine initialized (hooks_installed=%d)", g_hooks_installed);
    return JNI_TRUE;
}

/**
 * Add a path redirection rule.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeAddPathRedirection(
    JNIEnv* env, jobject thiz, jstring sourcePath, jstring targetPath)
{
    (void)thiz;
    const char* src = env->GetStringUTFChars(sourcePath, nullptr);
    const char* tgt = env->GetStringUTFChars(targetPath, nullptr);

    if (src && tgt) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_path_redirects[std::string(src)] = std::string(tgt);
        LOGI("Path redirect added: %s -> %s", src, tgt);
    }

    if (src) env->ReleaseStringUTFChars(sourcePath, src);
    if (tgt) env->ReleaseStringUTFChars(targetPath, tgt);
}

/**
 * Remove a path redirection rule.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeRemovePathRedirection(
    JNIEnv* env, jobject thiz, jstring sourcePath)
{
    (void)thiz;
    const char* src = env->GetStringUTFChars(sourcePath, nullptr);

    if (src) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_path_redirects.erase(std::string(src));
        LOGI("Path redirect removed: %s", src);
    }

    if (src) env->ReleaseStringUTFChars(sourcePath, src);
}

/**
 * Clear all path redirection rules.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeClearPathRedirections(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_path_redirects.clear();
    LOGI("All path redirects cleared");
}

/**
 * Set up /proc/self spoofing at native level.
 * Spoofs cmdline, comm, exe, and maps filtering.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSpoofProcSelf(
    JNIEnv* env, jobject thiz, jint pid, jstring packageName)
{
    (void)thiz;
    const char* pkg = env->GetStringUTFChars(packageName, nullptr);
    if (pkg) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_spoofed_pid = pid;
        g_spoofed_package_name = std::string(pkg);
        LOGI("/proc/self spoof set: pid=%d, pkg=%s", pid, pkg);
        env->ReleaseStringUTFChars(packageName, pkg);
    }
}

/**
 * Rename the calling thread/process to the guest's process name:
 * prctl(PR_SET_NAME) sets the kernel comm, which is what /proc/self/stat,
 * /proc/self/status (Name), task/<tid>/comm and ps all report. Doing it
 * at the source makes the identity right on channels no read-path hook
 * can cover (e.g. the guest's forked children inspecting their parent,
 * or anything reading /proc from outside the hooked libraries).
 * MUST match Kotlin: nativeSetProcessName(name: String)
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetProcessName(
    JNIEnv* env, jobject thiz, jstring name)
{
    (void)thiz;
    const char* n = env->GetStringUTFChars(name, nullptr);
    if (n) {
        // Kernel comm holds at most 15 visible chars (TASK_COMM_LEN-1)
        char comm[16];
        strncpy(comm, n, sizeof(comm) - 1);
        comm[sizeof(comm) - 1] = '\0';
        prctl(PR_SET_NAME, comm, 0, 0, 0);
        LOGI("process renamed: comm=%s", comm);
        env->ReleaseStringUTFChars(name, n);
    }
}

/**
 * =====================================================================
 * Seccomp raw-syscall diagnostic
 * =====================================================================
 * Every /proc fake the GOT hooks serve sits behind libc. A library
 * that issues svc instructions directly (a standard anti-hook
 * technique for strong packers) never touches libc and always sees
 * the REAL /proc — which would perfectly explain why no amount of
 * read-path spoofing changed the SecNeo outcome.
 *
 * This installs a seccomp filter that TRAPs the path-bearing
 * syscalls (openat, openat2, readlinkat, faccessat, faccessat2,
 * newfstatat) process-wide. A SIGSYS handler attributes each trap to
 * the loaded module containing the svc PC, logs the interesting ones
 * (any /proc path, any call from a packer library, any unattributed
 * PC) to a diag file, then EMULATES the call unchanged through a
 * one-instruction trampoline — the only IP the filter lets through
 * for these numbers — and resumes the thread. Diagnostic only: no
 * result is ever altered. The handler uses no libc calls (manual
 * formatting, trampoline write), so it is safe on any thread.
 * =====================================================================
 */
#include <signal.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 0
#endif
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#if defined(__aarch64__)
// The trampoline: the only svc the filter allows for trapped numbers.
// x0 = nr, x1..x4 = syscall args (C calling convention); the asm
// shuffles them into syscall registers. nv_seccomp_svc_point is the
// exact address of the svc instruction, baked into the BPF program.
__asm__(
    ".text\n"
    ".globl nv_seccomp_svc\n"
    ".type nv_seccomp_svc, %function\n"
    "nv_seccomp_svc:\n"
    "    mov x8, x0\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov x2, x3\n"
    "    mov x3, x4\n"
    ".globl nv_seccomp_svc_point\n"
    "nv_seccomp_svc_point:\n"
    "    svc #0\n"
    "    ret\n");
extern "C" long nv_seccomp_svc(long nr, long a0, long a1, long a2, long a3);
extern "C" char nv_seccomp_svc_point;

namespace {

struct ScModule {
    uintptr_t lo, hi;
    char name[48];
};

// Guest package name captured at arm time for the handler's pure-C
// path rewriting (the std::string spoof globals are not handler-safe).
char g_sc_guest_pkg[128] = {0};
int sc_rewrite_fd_target(const char* in, char* out, int cap);

ScModule g_sc_modules[2048];
volatile int g_sc_module_count = 0;
volatile int g_sc_log_fd = -1;
volatile long g_sc_logged = 0;
struct sigaction g_sc_prev_action;
__thread volatile int g_sc_in_handler = 0;

int sc_phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    if (g_sc_module_count >= 2048) return 0;
    uintptr_t lo = ~static_cast<uintptr_t>(0), hi = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)& p = info->dlpi_phdr[i];
        if (p.p_type != PT_LOAD) continue;
        uintptr_t s = info->dlpi_addr + p.p_vaddr;
        uintptr_t e = s + p.p_memsz;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (hi == 0) return 0;
    ScModule& m = g_sc_modules[g_sc_module_count];
    m.lo = lo;
    m.hi = hi;
    const char* n = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "[exe]";
    const char* base = n;
    for (const char* p = n; *p; p++) if (*p == '/') base = p + 1;
    size_t i = 0;
    for (; base[i] && i < sizeof(m.name) - 1; i++) m.name[i] = base[i];
    m.name[i] = 0;
    g_sc_module_count++;
    return 0;
}

const ScModule* sc_find(uintptr_t pc) {
    int count = g_sc_module_count;
    for (int i = 0; i < count; i++) {
        if (pc >= g_sc_modules[i].lo && pc < g_sc_modules[i].hi) return &g_sc_modules[i];
    }
    return nullptr;
}

const char* sc_strstr(const char* hay, const char* needle) {
    if (!*needle) return hay;
    for (const char* h = hay; *h; h++) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return h;
    }
    return nullptr;
}

bool sc_streq(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

void sc_app(char* buf, int& len, int cap, const char* s) {
    while (*s && len < cap - 1) buf[len++] = *s++;
}

void sc_app_dec(char* buf, int& len, int cap, long v) {
    unsigned long long u;
    if (v < 0) {
        if (len < cap - 1) buf[len++] = '-';
        u = static_cast<unsigned long long>(-(v + 1)) + 1;
    } else {
        u = static_cast<unsigned long long>(v);
    }
    char t[24];
    int n = 0;
    if (u == 0) t[n++] = '0';
    while (u) { t[n++] = static_cast<char>('0' + (u % 10)); u /= 10; }
    while (n > 0 && len < cap - 1) buf[len++] = t[--n];
}

void sc_app_hex(char* buf, int& len, int cap, unsigned long long v) {
    char t[20];
    int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) {
        int d = static_cast<int>(v & 15);
        t[n++] = static_cast<char>(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (n > 0 && len < cap - 1) buf[len++] = t[--n];
}

void sc_write_diag(long nr, const ScModule* mod, uintptr_t pc,
                   const char* path, long dirfd) {
    int fd = g_sc_log_fd;
    if (fd < 0) return;
    char buf[512];
    int len = 0;
    const int cap = static_cast<int>(sizeof(buf));
    sc_app(buf, len, cap, "SC");
    sc_app_dec(buf, len, cap, nr);
    sc_app(buf, len, cap, " tid=");
    sc_app_dec(buf, len, cap, nv_seccomp_svc(__NR_gettid, 0, 0, 0, 0));
    sc_app(buf, len, cap, " by=");
    if (mod) {
        sc_app(buf, len, cap, mod->name);
        sc_app(buf, len, cap, "+0x");
        sc_app_hex(buf, len, cap, pc - mod->lo);
    } else {
        sc_app(buf, len, cap, "?@0x");
        sc_app_hex(buf, len, cap, pc);
    }
    sc_app(buf, len, cap, " dirfd=");
    sc_app_dec(buf, len, cap, dirfd);
    sc_app(buf, len, cap, " path=");
    sc_app(buf, len, cap, path);
    sc_app(buf, len, cap, "\n");
    buf[len] = 0;
    nv_seccomp_svc(__NR_write, fd, reinterpret_cast<long>(buf), len, 0);
}

bool sc_is_trapped_nr(long nr) {
    return nr == __NR_openat || nr == __NR_openat2 || nr == __NR_readlinkat ||
           nr == __NR_faccessat || nr == __NR_faccessat2 || nr == __NR_newfstatat ||
           nr == 130 || nr == 131 || nr == 134 || nr == 135;
}

// ---- Phase 1b: serve rewritten /proc maps from the handler ----
// The shell reads /proc/self/maps through direct svc openat; feed it
// a memfd holding the transformed content (same rules as the GOT
// layer: guest virtual paths rewritten to stock-install form, lines
// belonging to the host/hook engine dropped). Pure C, trampoline
// syscalls only, static buffers under a spinlock.
const int kScMapsCap = 768 * 1024;
char g_sc_maps_raw[768 * 1024];
char g_sc_maps_out[768 * 1024];
volatile int g_sc_maps_lock = 0;

bool sc_path_is_maps(const char* p) {
    if (sc_streq(p, "/proc/self/maps")) return true;
    if (p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' &&
        p[4] == 'c' && p[5] == '/' && p[6] >= '0' && p[6] <= '9') {
        int i = 6;
        while (p[i] >= '0' && p[i] <= '9') i++;
        return sc_streq(p + i, "/maps");
    }
    return false;
}

long sc_serve_maps(long oflags) {
    if ((oflags & 3) != 0) return -1;  // O_RDONLY only
    while (__sync_lock_test_and_set(&g_sc_maps_lock, 1)) {
    }
    static const char kSelfMaps[] = "/proc/self/maps";
    long fd = nv_seccomp_svc(__NR_openat, -100,
                             reinterpret_cast<long>(kSelfMaps), 0, 0);
    if (fd < 0) {
        __sync_lock_release(&g_sc_maps_lock);
        return -1;
    }
    long total = 0;
    while (total < kScMapsCap) {
        long n = nv_seccomp_svc(__NR_read, fd,
                                reinterpret_cast<long>(g_sc_maps_raw + total),
                                kScMapsCap - total, 0);
        if (n < 0) { total = -1; break; }
        if (n == 0) break;
        total += n;
    }
    nv_seccomp_svc(__NR_close, fd, 0, 0, 0);
    if (total <= 0 || total >= kScMapsCap) {
        __sync_lock_release(&g_sc_maps_lock);
        return -1;
    }
    static const char* kHidden[] = {"nextvm", "lsplant", "dobby", "bhook",
                                    "xhook", "substrate", "xposed"};
    long olen = 0;
    long pos = 0;
    while (pos < total) {
        long eol = pos;
        while (eol < total && g_sc_maps_raw[eol] != '\n') eol++;
        if (eol < total) eol++;  // include newline
        // Locate the pathname: first '/' after the inode column —
        // approximated by the first '/' in the line (the address and
        // perms fields contain none).
        long ps = -1;
        for (long i = pos; i < eol; i++) {
            if (g_sc_maps_raw[i] == '/') { ps = i; break; }
        }
        bool drop = false;
        char rw[512];
        int rlen = -1;
        long path_len = 0;
        if (ps >= 0) {
            path_len = eol - ps;
            if (path_len > 0 && g_sc_maps_raw[eol - 1] == '\n') path_len--;
            if (path_len > 500) path_len = 0;  // leave unrewritten
            if (path_len > 0) {
                char pbuf[512];
                for (long i = 0; i < path_len; i++) pbuf[i] = g_sc_maps_raw[ps + i];
                pbuf[path_len] = 0;
                if (sc_strstr(pbuf, "/files/virtual/apks/") ||
                    sc_strstr(pbuf, "/files/virtual/data/")) {
                    rlen = sc_rewrite_fd_target(pbuf, rw, 500);
                } else {
                    for (int k = 0; k < 7; k++) {
                        if (sc_strstr(pbuf, kHidden[k])) { drop = true; break; }
                    }
                }
            }
        }
        if (!drop) {
            long head = (ps >= 0) ? (ps - pos) : (eol - pos);
            if (olen + head + (rlen > 0 ? rlen : 0) + 2 >= kScMapsCap) {
                __sync_lock_release(&g_sc_maps_lock);
                return -1;
            }
            for (long i = 0; i < head; i++) g_sc_maps_out[olen++] = g_sc_maps_raw[pos + i];
            if (ps >= 0 && rlen > 0) {
                for (int i = 0; i < rlen; i++) g_sc_maps_out[olen++] = rw[i];
                g_sc_maps_out[olen++] = '\n';
            } else if (ps >= 0) {
                for (long i = ps; i < eol; i++) g_sc_maps_out[olen++] = g_sc_maps_raw[i];
            }
        }
        pos = eol;
    }
    long mfd = nv_seccomp_svc(__NR_memfd_create,
                              reinterpret_cast<long>("jit-cache"),
                              (oflags & 02000000) ? 1 : 0, 0, 0);
    if (mfd < 0) {
        __sync_lock_release(&g_sc_maps_lock);
        return -1;
    }
    long written = 0;
    bool ok = true;
    while (written < olen) {
        long n = nv_seccomp_svc(__NR_write, mfd,
                                reinterpret_cast<long>(g_sc_maps_out + written),
                                olen - written, 0);
        if (n <= 0) { ok = false; break; }
        written += n;
    }
    if (ok) nv_seccomp_svc(__NR_lseek, mfd, 0, 0, 0);
    if (!ok) {
        nv_seccomp_svc(__NR_close, mfd, 0, 0, 0);
        __sync_lock_release(&g_sc_maps_lock);
        return -1;
    }
    __sync_lock_release(&g_sc_maps_lock);
    return mfd;
}

// Lean mode (flag files/sc-lean): the handler is a pure passthrough
// — emulate via the trampoline and resume, with NO logging, NO
// serving, NO rewriting. Bisection tool for the trap path.
bool g_sc_lean = false;

void sc_handle(int sig, siginfo_t* info, void* uctx) {
    if (g_sc_lean && info->si_code == SYS_SECCOMP) {
        ucontext_t* uc = static_cast<ucontext_t*>(uctx);
        long r = nv_seccomp_svc(info->si_syscall,
                                uc->uc_mcontext.regs[0],
                                uc->uc_mcontext.regs[1],
                                uc->uc_mcontext.regs[2],
                                uc->uc_mcontext.regs[3]);
        uc->uc_mcontext.regs[0] = r;
        uc->uc_mcontext.pc =
            reinterpret_cast<uintptr_t>(info->si_call_addr) + 4;
        return;
    }
    // Debug probe: prove the handler runs and record what arrived,
    // before any branching. Bounded; written unconditionally so traps
    // on other threads cannot hide behind the reentrancy flag.
    if (g_sc_log_fd >= 0) {
        static volatile long probe_count = 0;
        if (probe_count < 100000) {
            probe_count++;
            char pb[160];
            int plen = 0;
            const int pcap = static_cast<int>(sizeof(pb));
            sc_app(pb, plen, pcap, "H code=");
            sc_app_dec(pb, plen, pcap, info->si_code);
            sc_app(pb, plen, pcap, " nr=");
            sc_app_dec(pb, plen, pcap, info->si_syscall);
            sc_app(pb, plen, pcap, " pc=0x");
            sc_app_hex(pb, plen, pcap,
                       reinterpret_cast<uintptr_t>(info->si_call_addr));
            sc_app(pb, plen, pcap, "\n");
            pb[plen] = 0;
            nv_seccomp_svc(__NR_write, g_sc_log_fd,
                           reinterpret_cast<long>(pb), plen, 0);
        }
    }
    if (info->si_code != SYS_SECCOMP || !sc_is_trapped_nr(info->si_syscall)) {
        // Foreign SIGSYS (e.g. a self-sent tgkill): mark it before chaining.
        if (g_sc_log_fd >= 0) {
            char xb[160];
            int xl = 0;
            const int xcap = static_cast<int>(sizeof(xb));
            sc_app(xb, xl, xcap, "X code=");
            sc_app_dec(xb, xl, xcap, info->si_code);
            sc_app(xb, xl, xcap, " nr=");
            sc_app_dec(xb, xl, xcap, info->si_syscall);
            sc_app(xb, xl, xcap, " pc=0x");
            sc_app_hex(xb, xl, xcap,
                       reinterpret_cast<uintptr_t>(info->si_call_addr));
            sc_app(xb, xl, xcap, "\n");
            nv_seccomp_svc(__NR_write, g_sc_log_fd,
                           reinterpret_cast<long>(xb), xl, 0);
        }
        // Not one of ours: chain to the previous disposition.
        if ((g_sc_prev_action.sa_flags & SA_SIGINFO) && g_sc_prev_action.sa_sigaction) {
            g_sc_prev_action.sa_sigaction(sig, info, uctx);
            return;
        }
        if (g_sc_prev_action.sa_handler == SIG_IGN) return;
        if (g_sc_prev_action.sa_handler &&
            g_sc_prev_action.sa_handler != SIG_DFL) {
            g_sc_prev_action.sa_handler(sig);
            return;
        }
        sigaction(SIGSYS, &g_sc_prev_action, nullptr);
        raise(sig);
        return;
    }

    ucontext_t* uc = static_cast<ucontext_t*>(uctx);
    long nr = info->si_syscall;
    long a0 = uc->uc_mcontext.regs[0];
    long a1 = uc->uc_mcontext.regs[1];
    long a2 = uc->uc_mcontext.regs[2];
    long a3 = uc->uc_mcontext.regs[3];

    // Signal-channel syscalls: the only way to weaponize SIGSYS
    // against this filter (block it, reset its disposition, or send
    // it directly). Log every call; neutralize the SIGSYS cases.
    if (nr == 130 || nr == 131 || nr == 134 || nr == 135) {
        uintptr_t pc = reinterpret_cast<uintptr_t>(info->si_call_addr);
        const ScModule* mod = sc_find(pc);
        if (g_sc_log_fd >= 0) {
            static volatile long sig_logged = 0;
            if (sig_logged < 512) {
                sig_logged++;
                char sb[256];
                int sl = 0;
                const int scap = static_cast<int>(sizeof(sb));
                sc_app(sb, sl, scap, "S nr=");
                sc_app_dec(sb, sl, scap, nr);
                sc_app(sb, sl, scap, " a0=");
                sc_app_dec(sb, sl, scap, a0);
                sc_app(sb, sl, scap, " a1=0x");
                sc_app_hex(sb, sl, scap, static_cast<uintptr_t>(a1));
                if (nr == 135 && a1) {
                    sc_app(sb, sl, scap, " set=0x");
                    sc_app_hex(sb, sl, scap,
                               static_cast<uintptr_t>(
                                   *reinterpret_cast<unsigned long*>(a1)));
                }
                sc_app(sb, sl, scap, " a2=");
                sc_app_dec(sb, sl, scap, a2);
                sc_app(sb, sl, scap, " by=");
                sc_app(sb, sl, scap, mod ? mod->name : "?");
                sc_app(sb, sl, scap, "\n");
                sb[sl] = 0;
                nv_seccomp_svc(__NR_write, g_sc_log_fd,
                               reinterpret_cast<long>(sb), sl, 0);
            }
        }
        long ret = 0;
        if (nr == 135) {  // rt_sigprocmask
            if (a1 && (a0 == 0 || a0 == 2)) {  // BLOCK / SETMASK
                unsigned long m =
                    *reinterpret_cast<unsigned long*>(a1) &
                    ~(1UL << 30);
                ret = nv_seccomp_svc(nr, a0,
                                     reinterpret_cast<long>(&m), a2, a3);
            } else {
                ret = nv_seccomp_svc(nr, a0, a1, a2, a3);
            }
        } else if (nr == 134) {  // rt_sigaction
            if (a0 == 31 && a1 != 0) {
                // Refuse SIGSYS disposition changes; fake the old
                // action as this handler and report success.
                if (a2) {
                    unsigned long* o =
                        reinterpret_cast<unsigned long*>(a2);
                    o[0] = reinterpret_cast<unsigned long>(
                        reinterpret_cast<void*>(&sc_handle));
                    o[1] = 4;  // SA_SIGINFO
                    o[2] = 0;
                    o[3] = 0;
                }
                ret = 0;
            } else {
                ret = nv_seccomp_svc(nr, a0, a1, a2, a3);
            }
        } else {  // 130 tkill (sig in a1) / 131 tgkill (sig in a2)
            long sig_arg = (nr == 130) ? a1 : a2;
            if (sig_arg == 31) {
                ret = 0;  // swallowed: SIGSYS is never sent for them
            } else {
                ret = nv_seccomp_svc(nr, a0, a1, a2, a3);
            }
        }
        uc->uc_mcontext.regs[0] = ret;
        uc->uc_mcontext.pc =
            reinterpret_cast<uintptr_t>(info->si_call_addr) + 4;
        return;
    }

    char sc_path[168];
    sc_path[0] = 0;
    bool sc_have_path = false;
    if (!g_sc_in_handler) {
        g_sc_in_handler = 1;
        // All trapped numbers carry the path pointer in arg1.
        char path[168];
        int plen = 0;
        const char* p = reinterpret_cast<const char*>(static_cast<uintptr_t>(a1));
        if (p) {
            while (plen < static_cast<int>(sizeof(path)) - 1 && p[plen]) {
                path[plen] = p[plen];
                plen++;
            }
        }
        path[plen] = 0;
        for (int i = 0; i <= plen; i++) sc_path[i] = path[i];
        sc_have_path = true;
        bool proc_path = false;
        for (int i = 0; i + 4 < plen; i++) {
            if (path[i] == '/' && path[i + 1] == 'p' && path[i + 2] == 'r' &&
                path[i + 3] == 'o' && path[i + 4] == 'c') {
                proc_path = true;
                break;
            }
        }
        uintptr_t pc = reinterpret_cast<uintptr_t>(info->si_call_addr);
        const ScModule* mod = sc_find(pc);
        bool shell_lib = mod && sc_streq(mod->name, "libDexHelper.so");
        if ((proc_path || shell_lib || mod == nullptr) && g_sc_logged < 4000) {
            g_sc_logged++;
            sc_write_diag(nr, mod, pc, path, a0);
        }
        g_sc_in_handler = 0;
    }

    if (g_sc_log_fd >= 0) {
        char eb[8];
        int el = 0;
        sc_app(eb, el, 8, "E\n");
        nv_seccomp_svc(__NR_write, g_sc_log_fd,
                       reinterpret_cast<long>(eb), el, 0);
    }
    // Phase 1b: direct-svc readers of /proc maps get the rewritten
    // view via a memfd, exactly like the GOT layer serves libc readers.
    long ret = -1;
    bool served_maps = false;
    if (sc_have_path && (nr == __NR_openat || nr == __NR_openat2) &&
        sc_path_is_maps(sc_path)) {
        long oflags = -1;
        if (nr == __NR_openat) {
            oflags = a2;
        } else if (a2) {
            oflags = static_cast<long>(
                *reinterpret_cast<uint64_t*>(a2));  // open_how.flags
        }
        if (oflags >= 0) {
            long mfd = sc_serve_maps(oflags);
            if (mfd >= 0) {
                ret = mfd;
                served_maps = true;
                if (g_sc_log_fd >= 0) {
                    char mb[8];
                    int ml = 0;
                    sc_app(mb, ml, 8, "M\n");
                    nv_seccomp_svc(__NR_write, g_sc_log_fd,
                                   reinterpret_cast<long>(mb), ml, 0);
                }
            }
        }
    }
    if (!served_maps) {
        // Emulate the call unchanged through the trampoline and resume
        // just past the svc instruction.
        ret = nv_seccomp_svc(nr, a0, a1, a2, a3);
    }
    if (g_sc_log_fd >= 0) {
        char rb[8];
        int rl = 0;
        sc_app(rb, rl, 8, "R\n");
        nv_seccomp_svc(__NR_write, g_sc_log_fd,
                       reinterpret_cast<long>(rb), rl, 0);
    }
    // Phase 1a: fd symlink targets served to direct-svc callers must
    // be rewritten exactly like the GOT layer rewrites them for libc
    // callers — the raw targets betray the virtual layout.
    if (nr == __NR_readlinkat && ret > 0) {
        char* buf = reinterpret_cast<char*>(a2);
        long bufsz = a3;
        if (buf && bufsz > 1 && ret <= bufsz && ret < 500) {
            char orig[512];
            long n = ret;
            for (long i = 0; i < n; i++) orig[i] = buf[i];
            orig[n] = 0;
            char rw[512];
            int rlen = sc_rewrite_fd_target(orig, rw, 500);
            if (rlen > 0 && rlen < bufsz) {
                for (int i = 0; i < rlen; i++) buf[i] = rw[i];
                ret = rlen;
            }
        }
    }
    uc->uc_mcontext.regs[0] = ret;
    uc->uc_mcontext.pc = reinterpret_cast<uintptr_t>(info->si_call_addr) + 4;
}

}  // namespace

#endif  // __aarch64__

volatile sig_atomic_t g_sc_armed = 0;

static void sc_refresh_modules() {
#if defined(__aarch64__)
    if (!g_sc_armed) return;
    g_sc_module_count = 0;
    dl_iterate_phdr(sc_phdr_cb, nullptr);
#endif
}

namespace {

// Control-experiment switch, set in sc_arm when the flag file
bool g_sc_maps_real = false;

// files/sc-empty-filter exists: install the filter with impossible
// syscall numbers so NOTHING traps. Separates "a second filter
// exists" (Seccomp_filters=2) effects from trap-handling effects.
bool g_sc_empty_filter = false;

// Per-syscall trap mask (flag files/sc-trapmask, two hex chars):
// bit0 openat, bit1 openat2, bit2 readlinkat, bit3 faccessat,
// bit4 faccessat2, bit5 newfstatat. Masked-out numbers are replaced
// with impossible ones, like the empty-filter control.
unsigned g_sc_trap_mask = 0x3F;

// Installs the supervision filter. In notif mode the outcome is
// SECCOMP_RET_USER_NOTIF and the return value is the listener fd
// (>= 0); in trap mode the outcome is SECCOMP_RET_TRAP and the
// return value is 0. Returns -1 on failure.
//
// v18 rationale: RET_TRAP delivers a SIGSYS, and any thread that
// issues a trapped syscall while SIGSYS is transiently blocked
// (bionic thread start, signal plumbing) is force-killed by the
// kernel with the handler never running — this both caused false
// deaths and made the real killer invisible. USER_NOTIF generates
// no signal at all: a supervisor thread answers each call.
long sc_install_filter_ex(bool notif, bool with_signals = true,
                          bool tsync = true) {
#if !defined(__aarch64__)
    (void)notif;
    (void)with_signals;
    (void)tsync;
    return -1;
#else
    const unsigned s_kill = with_signals ? 129 : 0x3FFFFF10u;
    const unsigned s_tkill = with_signals ? 130 : 0x3FFFFF11u;
    const unsigned s_tgkill = with_signals ? 131 : 0x3FFFFF12u;
    const unsigned s_sigaction = with_signals ? 134 : 0x3FFFFF13u;
    const unsigned s_sigprocmask = with_signals ? 135 : 0x3FFFFF14u;
    const unsigned s_tgsigqueue = with_signals ? 297 : 0x3FFFFF15u;
    const unsigned s_pidfd = with_signals ? 424 : 0x3FFFFF16u;
    const unsigned t_openat = (g_sc_trap_mask & 0x01) ? __NR_openat : 0x3FFFFF00u;
    const unsigned t_openat2 = (g_sc_trap_mask & 0x02) ? __NR_openat2 : 0x3FFFFF01u;
    const unsigned t_readlinkat = (g_sc_trap_mask & 0x04) ? __NR_readlinkat : 0x3FFFFF02u;
    const unsigned t_faccessat = (g_sc_trap_mask & 0x08) ? __NR_faccessat : 0x3FFFFF03u;
    const unsigned t_faccessat2 = (g_sc_trap_mask & 0x10) ? __NR_faccessat2 : 0x3FFFFF04u;
    const unsigned t_newfstatat = (g_sc_trap_mask & 0x20) ? __NR_newfstatat : 0x3FFFFF05u;
    uintptr_t svc = reinterpret_cast<uintptr_t>(&nv_seccomp_svc_point);
    uint32_t lo = static_cast<uint32_t>(svc & 0xffffffffu);
    uint32_t hi = static_cast<uint32_t>(svc >> 32);
    const unsigned kOutcome = notif ? SECCOMP_RET_USER_NOTIF
                                    : SECCOMP_RET_TRAP;
    // Layout (24 insns): arch check -> nr dispatch (13 numbers,
    // indices 3..15) -> trampoline-IP check (17..21) -> OUTCOME
    // (22) / ALLOW (23). Signal-channel numbers are always in the
    // dispatch: under NOTIF they can be watched and neutralized
    // without any signal ever being generated.
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 21),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_openat, 13, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_openat2, 12, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_readlinkat, 11, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_faccessat, 10, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_faccessat2, 9, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_newfstatat, 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_kill, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_tkill, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_tgkill, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_sigaction, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_sigprocmask, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_tgsigqueue, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, s_pidfd, 1, 0),
        BPF_STMT(BPF_JMP | BPF_JA, 6),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, lo, 0, 3),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, lo + 8, 2, 0),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hi, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, kOutcome),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(sizeof(f) / sizeof(f[0]));
    prog.filter = f;

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (notif) {
        unsigned flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
        if (tsync) flags |= SECCOMP_FILTER_FLAG_TSYNC;
        long fd = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          flags, &prog);
        if (fd >= 0) {
            LOGI("seccomp-diag: USER_NOTIF filter installed, listener=%ld flags=0x%x",
                 fd, flags);
            return fd;
        }
        LOGE("seccomp-diag: USER_NOTIF install FAILED (errno=%d flags=0x%x)",
             errno, flags);
        return -1;
    }
    long rc = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (rc == 0) {
        LOGI("seccomp-diag: filter installed (TSYNC)");
        return 0;
    }
    int e1 = errno;
    rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    if (rc == 0) {
        LOGI("seccomp-diag: filter installed (prctl, single thread + inheritors)");
        return 0;
    }
    LOGE("seccomp-diag: filter install FAILED (seccomp errno=%d, prctl errno=%d)",
         e1, errno);
    return -1;
#endif
}

// Pure-C mirror of rewrite_virtual_path for fd symlink targets,
// used inside the SIGSYS handler (no allocation, no libc calls).
// Returns the rewritten length, or -1 when no rewrite applies.
#if defined(__aarch64__)
int sc_rewrite_fd_target(const char* in, char* out, int cap) {
    if (g_sc_guest_pkg[0] == 0) return -1;
    char core[512];
    int clen = 0;
    while (in[clen] && clen < 500) { core[clen] = in[clen]; clen++; }
    core[clen] = 0;
    bool deleted = false;
    if (clen >= 11 && sc_streq(core + clen - 11, " (deleted)")) {
        core[clen - 11] = 0;
        clen -= 11;
        deleted = true;
    }
    int olen = 0;
    auto emit = [&](const char* s) {
        while (*s && olen < cap - 12) out[olen++] = *s++;
    };
    auto emit_synth_apk = [&]() {
        emit("/data/app/~~VmK8x2==/");
        emit(g_sc_guest_pkg);
        emit("-VmK8x2==/base.apk");
    };
    const char* apks_marker = sc_strstr(core, "/files/virtual/apks/");
    const char* data_marker = sc_strstr(core, "/files/virtual/data/");
    if (apks_marker && clen >= 4 && sc_streq(core + clen - 4, ".apk")) {
        const char* fname = core + clen;
        while (fname > core && fname[-1] != '/') fname--;
        const char* usplit = sc_strstr(fname, "_split_");
        const char* split = usplit ? sc_strstr(fname, "split_") : nullptr;
        if (split) {
            emit("/data/app/~~VmK8x2==/");
            emit(g_sc_guest_pkg);
            emit("-VmK8x2==/");
            emit(split);
        } else {
            emit_synth_apk();
        }
    } else if (data_marker) {
        const char* rest = data_marker + 20;  // strlen("/files/virtual/data/")
        while (*rest && *rest != '/') rest++;
        if (*rest == '/') rest++;
        if (!*rest) return -1;
        if (rest[0] == 'l' && rest[1] == 'i' && rest[2] == 'b' && rest[3] == '/') {
            const char* b = rest + 4;
            const char* p = b;
            while (*p) { if (*p == '/') b = p + 1; p++; }
            emit("/data/app/~~VmK8x2==/");
            emit(g_sc_guest_pkg);
            emit("-VmK8x2==/lib/arm64/");
            emit(b);
        } else {
            emit("/data/data/");
            emit(g_sc_guest_pkg);
            emit("/");
            emit(rest);
        }
    } else if (sc_strstr(core, "nextvm")) {
        emit_synth_apk();
    } else {
        return -1;
    }
    if (deleted) emit(" (deleted)");
    out[olen] = 0;
    return olen;
}
#endif  // __aarch64__

#if defined(__aarch64__)
// Watchdog: sample the main thread's real signal masks and seccomp
// filter count from /proc/self/status, read raw through the
// trampoline (bypasses both the filter and the GOT spoof). Logs a WD
// line whenever the SIGSYS bit of SigBlk/SigCgt or the filter count
// changes — distinguishes the shell resetting our SIGSYS disposition
// (SigCgt bit drops), blocking SIGSYS (SigBlk bit rises), or stacking
// its own seccomp filter (Seccomp_filters rises) before the fatal
// trap that never reaches our handler.
// Per-thread blocked-SIGSYS census: a fatal trap can only bypass
// the handler on a thread whose mask blocks SIGSYS persistently, so
// sample every thread's SigBlk bit 30 plus its comm. A tid is logged
// (WD2) when the bit is set in two consecutive polls — handler
// occupancy alone rarely spans two 5ms polls, so persistent sightings
// name the threads that would die on their next trapped syscall.
struct ScTidState {
    long tid;
    int blocked_streak;
    int logged;
};
ScTidState g_sc_tid_states[256];

void sc_watchdog_threads() {
    static const char kTask[] = "/proc/self/task";
    long dfd = nv_seccomp_svc(__NR_openat, -100,
                              reinterpret_cast<long>(kTask),
                              0200000 /*O_DIRECTORY*/, 0);
    if (dfd < 0) return;
    char dbuf[4096];
    long n = nv_seccomp_svc(61 /*getdents64*/, dfd,
                            reinterpret_cast<long>(dbuf),
                            sizeof(dbuf), 0);
    nv_seccomp_svc(__NR_close, dfd, 0, 0, 0);
    if (n <= 0) return;
    long self = nv_seccomp_svc(__NR_getpid, 0, 0, 0, 0);
    long off = 0;
    while (off < n) {
        // linux_dirent64: ino(8) off(8) reclen(2) type(1) name[]
        unsigned short reclen =
            static_cast<unsigned short>(dbuf[off + 16]) |
            (static_cast<unsigned short>(dbuf[off + 17]) << 8);
        if (reclen == 0) break;
        const char* name = dbuf + off + 19;
        long tid = 0;
        bool numeric = name[0] >= '0' && name[0] <= '9';
        if (numeric) {
            for (int i = 0; name[i] >= '0' && name[i] <= '9'; i++)
                tid = tid * 10 + (name[i] - '0');
        }
        off += reclen;
        if (!numeric || tid == 0 || tid == self) continue;
        char path[96];
        int pl = 0;
        const int pcap = static_cast<int>(sizeof(path));
        sc_app(path, pl, pcap, "/proc/self/task/");
        sc_app_dec(path, pl, pcap, tid);
        sc_app(path, pl, pcap, "/status");
        path[pl] = 0;
        long fd = nv_seccomp_svc(__NR_openat, -100,
                                 reinterpret_cast<long>(path), 0, 0);
        if (fd < 0) continue;
        char sbuf[3072];
        long sn = nv_seccomp_svc(__NR_read, fd,
                                 reinterpret_cast<long>(sbuf),
                                 sizeof(sbuf) - 1, 0);
        nv_seccomp_svc(__NR_close, fd, 0, 0, 0);
        if (sn <= 0) continue;
        sbuf[sn] = 0;
        const char* bp = sc_strstr(sbuf, "SigBlk:");
        if (!bp) continue;
        bp += 7;
        while (*bp == '\t' || *bp == ' ') bp++;
        long v = 0;
        bool any = false;
        while ((*bp >= '0' && *bp <= '9') || (*bp >= 'a' && *bp <= 'f')) {
            v = v * 16 + (*bp <= '9' ? *bp - '0' : *bp - 'a' + 10);
            bp++;
            any = true;
        }
        if (!any) continue;
        int blocked = static_cast<int>((v >> 30) & 1);
        ScTidState* st = nullptr;
        for (int i = 0; i < 256; i++) {
            if (g_sc_tid_states[i].tid == tid) { st = &g_sc_tid_states[i]; break; }
            if (g_sc_tid_states[i].tid == 0) {
                g_sc_tid_states[i].tid = tid;
                st = &g_sc_tid_states[i];
                break;
            }
        }
        if (!st) continue;
        if (blocked) {
            st->blocked_streak++;
            if (st->blocked_streak >= 2 && !st->logged && g_sc_log_fd >= 0) {
                st->logged = 1;
                char comm[64];
                int cl = 0;
                const int ccap = static_cast<int>(sizeof(comm));
                sc_app(comm, cl, ccap, "/proc/self/task/");
                sc_app_dec(comm, cl, ccap, tid);
                sc_app(comm, cl, ccap, "/comm");
                comm[cl] = 0;
                char cname[64];
                cname[0] = 0;
                long cfd = nv_seccomp_svc(__NR_openat, -100,
                                          reinterpret_cast<long>(comm), 0, 0);
                if (cfd >= 0) {
                    long cn = nv_seccomp_svc(__NR_read, cfd,
                                              reinterpret_cast<long>(cname),
                                              sizeof(cname) - 1, 0);
                    nv_seccomp_svc(__NR_close, cfd, 0, 0, 0);
                    if (cn > 0) {
                        if (cname[cn - 1] == '\n') cn--;
                        cname[cn] = 0;
                    }
                }
                char line[192];
                int l = snprintf(line, sizeof(line),
                                 "WD2 tid=%ld comm=%s blk31=1 streak=%d\n",
                                 tid, cname, st->blocked_streak);
                if (l > 0) {
                    ssize_t u = write(g_sc_log_fd, line, l);
                    (void)u;
                }
            }
        } else {
            st->blocked_streak = 0;
        }
    }
}

void* sc_watchdog_main(void*) {
    char buf[4096];
    long prev_blk = -2, prev_cgt = -2, prev_filters = -2;
    static const char kStatus[] = "/proc/self/status";
    for (int iter = 0; iter < 4000 && g_sc_armed; iter++) {
        sc_watchdog_threads();
        long fd = nv_seccomp_svc(__NR_openat, -100,
                                 reinterpret_cast<long>(kStatus), 0, 0);
        if (fd >= 0) {
            long n = nv_seccomp_svc(__NR_read, fd,
                                     reinterpret_cast<long>(buf),
                                     sizeof(buf) - 1, 0);
            nv_seccomp_svc(__NR_close, fd, 0, 0, 0);
            if (n > 0) {
                buf[n] = 0;
                auto hexfield = [&buf](const char* name) -> long {
                    const char* p = sc_strstr(buf, name);
                    if (!p) return -1;
                    p += strlen(name);
                    while (*p == '\t' || *p == ' ') p++;
                    long v = 0;
                    bool any = false;
                    while ((*p >= '0' && *p <= '9') ||
                           (*p >= 'a' && *p <= 'f')) {
                        v = v * 16 + (*p <= '9' ? *p - '0' : *p - 'a' + 10);
                        p++;
                        any = true;
                    }
                    return any ? v : -1;
                };
                long blk = hexfield("SigBlk:");
                long cgt = hexfield("SigCgt:");
                long filters = -1;
                const char* fp = sc_strstr(buf, "Seccomp_filters:");
                if (fp) {
                    fp += 16;
                    while (*fp == '\t' || *fp == ' ') fp++;
                    long v = 0;
                    bool any = false;
                    while (*fp >= '0' && *fp <= '9') {
                        v = v * 10 + (*fp - '0');
                        fp++;
                        any = true;
                    }
                    filters = any ? v : -1;
                }
                long blk31 = (blk >= 0) ? ((blk >> 30) & 1) : -1;
                long cgt31 = (cgt >= 0) ? ((cgt >> 30) & 1) : -1;
                if (blk31 != prev_blk || cgt31 != prev_cgt ||
                    filters != prev_filters) {
                    prev_blk = blk31;
                    prev_cgt = cgt31;
                    prev_filters = filters;
                    if (g_sc_log_fd >= 0) {
                        char line[160];
                        int l = snprintf(line, sizeof(line),
                                         "WD blk31=%ld cgt31=%ld filters=%ld iter=%d\n",
                                         blk31, cgt31, filters, iter);
                        if (l > 0) {
                            ssize_t u = write(g_sc_log_fd, line, l);
                            (void)u;
                        }
                    }
                }
            }
        }
        usleep(5000);
    }
    return nullptr;
}
#endif  // __aarch64__

// ---- USER_NOTIF supervisor (v18) ----
// In this mode no SIGSYS handler exists at all. The supervisor
// thread answers every trapped syscall through the listener fd, so
// a caller with SIGSYS blocked simply waits for the answer instead
// of being force-killed by the kernel, and signal-channel calls
// (kill/tkill/tgkill/sigaction/sigprocmask/...) can be watched and
// neutralized directly.
#if defined(__aarch64__)
int g_sc_listener_fd = -1;
volatile int g_sc_mode = 0;  // 0 pending, 1 notif, 2 trap, 3 off

// The NDK's <linux/seccomp.h> omits SECCOMP_IOCTL_NOTIF_SIZES and
// its sibling macros need <sys/ioctl.h> for _IOW/_IOWR; spell the
// numbers out with the header's struct types (stable UAPI).
#define SC_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#define SC_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
#define SC_NOTIF_ID_VALID _IOW('!', 2, uint64_t)
#define SC_NOTIF_ADDFD _IOW('!', 3, struct seccomp_notif_addfd)

void sc_slogf(const char* fmt, ...) {
    if (g_sc_log_fd < 0) return;
    char buf[640];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        ssize_t u = write(g_sc_log_fd, buf, n);
        (void)u;
    }
}

bool sc_tid_is_own_thread(long tid) {
    // Authoritative test: the Tgid in /proc/<tid>/status, read with
    // plain libc (the supervisor is unfiltered, so no trampoline is
    // needed). The earlier trampoline openat of /proc/self/task/<tid>
    // returned false for this process's own main thread in the
    // supervisor context (v23 misrouted its maps serve to ADDFD and
    // wedged it), so that mechanism is no longer trusted here.
    char p[64];
    snprintf(p, sizeof(p), "/proc/%ld/status", tid);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return tid == static_cast<long>(getpid());
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = 0;
    const char* t = strstr(buf, "Tgid:");
    if (!t) return false;
    long tg = strtol(t + 5, nullptr, 10);
    return tg == static_cast<long>(getpid());
}

// Copies a NUL-terminated string out of the notifying thread's
// address space: directly when it is one of our own threads, via
// /proc/<tid>/mem when it is a forked descendant.
int sc_copy_remote_str(long tid, unsigned long addr, char* out, int cap) {
    out[0] = 0;
    if (!addr) return 0;
    if (sc_tid_is_own_thread(tid)) {
        const char* p = reinterpret_cast<const char*>(
            static_cast<uintptr_t>(addr));
        int n = 0;
        while (n < cap - 1 && p[n]) {
            out[n] = p[n];
            n++;
        }
        out[n] = 0;
        return n;
    }
    char mp[64];
    int l = 0;
    const int mcap = static_cast<int>(sizeof(mp));
    sc_app(mp, l, mcap, "/proc/");
    sc_app_dec(mp, l, mcap, tid);
    sc_app(mp, l, mcap, "/mem");
    mp[l] = 0;
    long fd = nv_seccomp_svc(__NR_openat, -100,
                             reinterpret_cast<long>(mp), 0, 0);
    if (fd >= 0) {
        int n = 0;
        while (n < cap - 1) {
            char c = 0;
            long r = nv_seccomp_svc(67 /*pread64*/, fd,
                                    reinterpret_cast<long>(&c), 1,
                                    static_cast<long>(addr) + n);
            if (r != 1 || c == 0) break;
            out[n++] = c;
        }
        out[n] = 0;
        nv_seccomp_svc(__NR_close, fd, 0, 0, 0);
        if (n > 0) return n;
    }
    // Fallback: the descendant is a fork of this process and made
    // itself undumpable, so its memory is unreadable — but its
    // static strings (checklists, path tables) were written before
    // the fork and are byte-identical at the same address in our
    // own address space. Read them via /proc/self/mem (fails
    // cleanly on unmapped addresses instead of faulting).
    long sfd = nv_seccomp_svc(__NR_openat, -100,
                              reinterpret_cast<long>("/proc/self/mem"),
                              0, 0);
    if (sfd < 0) return 0;
    int n = 0;
    while (n < cap - 1) {
        char c = 0;
        long r = nv_seccomp_svc(67 /*pread64*/, sfd,
                                reinterpret_cast<long>(&c), 1,
                                static_cast<long>(addr) + n);
        if (r != 1 || c == 0) break;
        out[n++] = c;
    }
    out[n] = 0;
    nv_seccomp_svc(__NR_close, sfd, 0, 0, 0);
    return n;
}

// Serves one notification. Returns true when the notification was
// fully consumed by SECCOMP_IOCTL_NOTIF_ADDFD (no SEND needed).
bool sc_serve_notif(struct seccomp_notif* req,
                    struct seccomp_notif_resp* resp) {
    resp->id = req->id;
    resp->val = 0;
    resp->error = 0;
    resp->flags = 0;
    long nr = req->data.nr;
    unsigned long a0 = req->data.args[0];
    unsigned long a1 = req->data.args[1];
    unsigned long a2 = req->data.args[2];
    unsigned long a3 = req->data.args[3];
    uintptr_t ip = static_cast<uintptr_t>(req->data.instruction_pointer);
    const ScModule* mod = sc_find(ip);
    const char* modname = mod ? mod->name : "?";

    // Signal-channel calls first: watch them, and never let a
    // SIGSYS be sent at the guest's request.
    long sig = -1;
    if (nr == 129 || nr == 130 || nr == 424) sig = static_cast<long>(a1);
    if (nr == 131 || nr == 297) sig = static_cast<long>(a2);
    if (sig >= 0) {
        if (sig == 31) {
            sc_slogf("NS nr=%ld sig=31 SWALLOWED by=%s tid=%u\n",
                     nr, modname, req->pid);
            resp->val = 0;
            return false;
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        return false;
    }
    if (nr == 134) {  // rt_sigaction
        if (a0 == 31 && a1 != 0) {
            sc_slogf("NS134 set SIGSYS disposition by=%s tid=%u\n",
                     modname, req->pid);
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        return false;
    }
    if (nr == 135) {  // rt_sigprocmask
        if (sc_tid_is_own_thread(req->pid) && a1 &&
            (a0 == 0 || a0 == 2)) {
            unsigned long m = *reinterpret_cast<unsigned long*>(
                static_cast<uintptr_t>(a1));
            if ((m >> 30) & 1) {
                sc_slogf("NS135 block SIGSYS how=%lu by=%s tid=%u\n",
                         a0, modname, req->pid);
            }
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        return false;
    }

    if (nr == __NR_openat || nr == __NR_openat2 ||
        nr == __NR_readlinkat || nr == __NR_faccessat ||
        nr == __NR_faccessat2 || nr == __NR_newfstatat) {
        char path[256];
        sc_copy_remote_str(req->pid, a1, path, sizeof(path));
        bool proc_path = false;
        for (int i = 0; path[i] && i + 4 < 250; i++) {
            if (path[i] == '/' && path[i + 1] == 'p' &&
                path[i + 2] == 'r' && path[i + 3] == 'o' &&
                path[i + 4] == 'c') {
                proc_path = true;
                break;
            }
        }
        bool shell_lib = mod && sc_streq(mod->name, "libDexHelper.so");
        if ((proc_path || shell_lib || mod == nullptr) &&
            g_sc_logged < 4000) {
            g_sc_logged++;
            sc_slogf("SC%ld tid=%u by=%s+0x%lx dirfd=%ld path=%s\n",
                     nr, req->pid, modname,
                     mod ? static_cast<unsigned long>(ip - mod->lo) : 0UL,
                     static_cast<long>(a0), path);
        }
        if (nr == __NR_readlinkat) {
            if (!sc_tid_is_own_thread(req->pid)) {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                return false;
            }
            long r = nv_seccomp_svc(nr, static_cast<long>(a0),
                                    static_cast<long>(a1),
                                    static_cast<long>(a2),
                                    static_cast<long>(a3));
            if (r < 0) {
                // Let the kernel produce the genuine result.
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                return false;
            }
            if (r > 0) {
                char* buf = reinterpret_cast<char*>(
                    static_cast<uintptr_t>(a2));
                long bufsz = static_cast<long>(a3);
                if (buf && bufsz > 1 && r <= bufsz && r < 500) {
                    char orig[512];
                    for (long i = 0; i < r; i++) orig[i] = buf[i];
                    orig[r] = 0;
                    char rw[512];
                    int rlen = sc_rewrite_fd_target(orig, rw, 500);
                    if (rlen > 0 && rlen < bufsz) {
                        for (int i = 0; i < rlen; i++) buf[i] = rw[i];
                        r = rlen;
                    }
                }
            }
            resp->val = r;
            return false;
        }
        if ((nr == __NR_openat || nr == __NR_openat2) &&
            sc_path_is_maps(path)) {
            long oflags = -1;
            if (nr == __NR_openat) {
                oflags = static_cast<long>(a2);
            } else if (a2 && sc_tid_is_own_thread(req->pid)) {
                oflags = static_cast<long>(
                    *reinterpret_cast<uint64_t*>(
                        static_cast<uintptr_t>(a2)));
            }
            if (oflags >= 0 && (oflags & 3) == 0 &&
                !g_sc_maps_real) {
                long mfd = sc_serve_maps(oflags);
                if (mfd >= 0) {
                    uint64_t idv = req->id;
                    if (ioctl(g_sc_listener_fd, SC_NOTIF_ID_VALID,
                              &idv) != 0) {
                        close(static_cast<int>(mfd));
                        sc_slogf("NMAPDROP pid=%u (died during "
                                 "serve)\n", req->pid);
                        return true;
                    }
                    if (sc_tid_is_own_thread(req->pid)) {
                        // Same-process supervision: supervisor and
                        // target share one fd table, so the memfd
                        // is already a valid fd for the caller.
                        // Answer with the fd number directly in the
                        // response value — no ADDFD (on this kernel
                        // an in-process ADDFD answered "success" yet
                        // the caller never resumed; v19-v21 all
                        // wedged right there). Ownership passes to
                        // the caller: do NOT close.
                        resp->val = mfd;
                        resp->error = 0;
                        resp->flags = 0;
                        sc_slogf("NMAP tid=%u fd=%ld (direct)\n",
                                 req->pid, mfd);
                        return false;
                    }
                    // Descendant (forked checker): its fd table is
                    // a fork copy, so our memfd number means nothing
                    // there — install it into the child's table with
                    // ADDFD (the standard cross-process use case).
                    struct seccomp_notif_addfd ad;
                    memset(&ad, 0, sizeof(ad));
                    ad.id = req->id;
                    ad.srcfd = static_cast<unsigned>(mfd);
                    ad.newfd_flags = (oflags & 02000000) ? 02000000 : 0;
                    long nfd = ioctl(g_sc_listener_fd,
                                     SC_NOTIF_ADDFD, &ad);
                    close(static_cast<int>(mfd));
                    if (nfd >= 0) {
                        sc_slogf("NMAPX tid=%u fd=%ld\n", req->pid, nfd);
                        return true;
                    }
                    sc_slogf("NMAPXFAIL tid=%u errno=%d\n",
                             req->pid, errno);
                }
            }
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            return false;
        }
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        return false;
    }
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    return false;
}

void* sc_supervisor_thread(void*) {
    while (g_sc_mode == 0) usleep(200);
    if (g_sc_mode == 2) {
        sc_watchdog_main(nullptr);
        return nullptr;
    }
    if (g_sc_mode != 1) return nullptr;
    fcntl(g_sc_listener_fd, F_SETFL, O_NONBLOCK);
    static volatile int sc_pool_spawned = 0;
    bool is_first_worker =
        __sync_bool_compare_and_swap(&sc_pool_spawned, 0, 1);
    if (is_first_worker) {
        for (int i = 1; i < 4; i++) {
            pthread_t extra;
            pthread_create(&extra, nullptr, sc_supervisor_thread,
                           nullptr);
        }
    }
    void* reqbuf = malloc(sizeof(struct seccomp_notif));
    void* respbuf = malloc(sizeof(struct seccomp_notif_resp));
    if (!reqbuf || !respbuf) return nullptr;
    static volatile unsigned sc_serve_seq = 0;
    int idle = 0;
    while (g_sc_armed) {
        memset(reqbuf, 0, sizeof(struct seccomp_notif));
        if (ioctl(g_sc_listener_fd, SC_NOTIF_RECV, reqbuf) == 0) {
            struct seccomp_notif* req =
                static_cast<struct seccomp_notif*>(reqbuf);
            uint64_t id = req->id;
            unsigned seq = ++sc_serve_seq;
            if (ioctl(g_sc_listener_fd, SC_NOTIF_ID_VALID, &id) == 0) {
                struct seccomp_notif_resp* resp =
                    static_cast<struct seccomp_notif_resp*>(respbuf);
                memset(resp, 0, sizeof(struct seccomp_notif_resp));
                bool consumed = sc_serve_notif(req, resp);
                if (!consumed) {
                    uint64_t id2 = req->id;
                    if (ioctl(g_sc_listener_fd, SC_NOTIF_ID_VALID,
                              &id2) == 0) {
                        resp->id = req->id;
                        long sr = ioctl(g_sc_listener_fd,
                                        SC_NOTIF_SEND, resp);
                        if (sr != 0) {
                            sc_slogf("SENDFAIL #%u nr=%lld "
                                     "errno=%d\n",
                                     seq,
                                     (long long)req->data.nr,
                                     errno);
                        }
                    } else {
                        sc_slogf("DROP #%u nr=%lld pid=%u (died "
                                 "during serve)\n",
                                 seq, (long long)req->data.nr,
                                 req->pid);
                    }
                }
            }
        } else {
            usleep(1000);
            if (is_first_worker && (++idle % 200) == 0) {
                sc_watchdog_threads();
            }
        }
    }
    return nullptr;
}
#endif  // __aarch64__

int sc_arm(const char* log_path) {
#if !defined(__aarch64__)
    (void)log_path;
    return -1;
#else
    if (g_sc_armed) return 0;
    g_sc_module_count = 0;
    dl_iterate_phdr(sc_phdr_cb, nullptr);

    // Capture the guest package for handler-side rewriting.
    {
        const std::string& pkg = g_spoofed_package_name;
        size_t n = pkg.size();
        if (n > 120) n = 120;
        memcpy(g_sc_guest_pkg, pkg.data(), n);
        g_sc_guest_pkg[n] = 0;
    }

    // Per-process log file: <log_path>-<pid>.log, so a dying stub's
    // evidence is not wiped by the next stub's arm.
    char eff_path[512];
    {
        int el = 0;
        const int ecap = static_cast<int>(sizeof(eff_path));
        sc_app(eff_path, el, ecap, log_path);
        sc_app(eff_path, el, ecap, "-");
        sc_app_dec(eff_path, el, ecap, getpid());
        sc_app(eff_path, el, ecap, ".log");
        eff_path[el] = 0;
    }

    int fd = open(eff_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    g_sc_log_fd = fd;
    if (fd >= 0) {
        char hdr[256];
        int len = 0;
        const int cap = static_cast<int>(sizeof(hdr));
        sc_app(hdr, len, cap, "SECCOMP-DIAG armed, modules=");
        sc_app_dec(hdr, len, cap, g_sc_module_count);
        sc_app(hdr, len, cap, " trampoline=0x");
        sc_app_hex(hdr, len, cap,
                   reinterpret_cast<uintptr_t>(&nv_seccomp_svc_point));
        sc_app(hdr, len, cap, "\n");
        hdr[len] = 0;
        ssize_t unused = write(fd, hdr, len);
        (void)unused;
        // Dump the module table once per arm so unattributed trap PCs
        // can be resolved offline against the same process's ranges.
        for (int i = 0; i < g_sc_module_count; i++) {
            char ml[512];
            int mlen = 0;
            const int mcap = static_cast<int>(sizeof(ml));
            sc_app(ml, mlen, mcap, "MOD 0x");
            sc_app_hex(ml, mlen, mcap, g_sc_modules[i].lo);
            sc_app(ml, mlen, mcap, "-0x");
            sc_app_hex(ml, mlen, mcap, g_sc_modules[i].hi);
            sc_app(ml, mlen, mcap, " ");
            sc_app(ml, mlen, mcap, g_sc_modules[i].name);
            sc_app(ml, mlen, mcap, "\n");
            ml[mlen] = 0;
            ssize_t u2 = write(fd, ml, mlen);
            (void)u2;
        }
    }

    {
        // Control flag: <log dir>/sc-empty-filter
        char flag[512];
        int fl = 0;
        const int fcap = static_cast<int>(sizeof(flag));
        const char* slash = nullptr;
        for (const char* p = log_path; *p; p++) {
            if (*p == '/') slash = p;
        }
        if (slash) {
            for (const char* p = log_path; p < slash; p++) {
                if (fl < fcap - 1) flag[fl++] = *p;
            }
        }
        sc_app(flag, fl, fcap, "/sc-empty-filter");
        flag[fl] = 0;
        int ffd = open(flag, O_RDONLY);
        if (ffd >= 0) {
            close(ffd);
            g_sc_empty_filter = true;
            if (g_sc_log_fd >= 0) {
                const char note[] = "MODE empty-filter (control)\n";
                ssize_t u = write(g_sc_log_fd, note, sizeof(note) - 1);
                (void)u;
            }
        }
    }
    {
        // Bisection flags: sc-lean (existence), sc-trapmask (2 hex).
        char flag2[512];
        const int fcap = static_cast<int>(sizeof(flag2));
        const char* slash = nullptr;
        for (const char* p = log_path; *p; p++) {
            if (*p == '/') slash = p;
        }
        const int dirlen = slash ? static_cast<int>(slash - log_path) : 0;
        auto sibling = [&](const char* leaf) -> const char* {
            int fl = 0;
            for (int i = 0; i < dirlen && fl < fcap - 24; i++)
                flag2[fl++] = log_path[i];
            sc_app(flag2, fl, fcap, leaf);
            flag2[fl] = 0;
            return flag2;
        };
        int lfd = open(sibling("/sc-lean"), O_RDONLY);
        if (lfd >= 0) {
            close(lfd);
            g_sc_lean = true;
        }
        int rfd = open(sibling("/sc-maps-real"), O_RDONLY);
        if (rfd >= 0) {
            close(rfd);
            g_sc_maps_real = true;
        }
        int mfd = open(sibling("/sc-trapmask"), O_RDONLY);
        if (mfd >= 0) {
            char mb[8] = {0};
            ssize_t mn = read(mfd, mb, sizeof(mb) - 1);
            close(mfd);
            if (mn > 0) {
                unsigned v = 0;
                bool any = false;
                for (int i = 0; i < mn; i++) {
                    char c = mb[i];
                    int d = (c >= '0' && c <= '9') ? c - '0'
                            : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                            : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                                                     : -1;
                    if (d < 0) break;
                    v = v * 16 + static_cast<unsigned>(d);
                    any = true;
                }
                if (any) g_sc_trap_mask = v & 0x3F;
            }
        }
        if (g_sc_empty_filter) g_sc_trap_mask = 0;
        if (g_sc_log_fd >= 0) {
            char note[96];
            int nl = 0;
            const int ncap = static_cast<int>(sizeof(note));
            sc_app(note, nl, ncap, "MODE lean=");
            sc_app_dec(note, nl, ncap, g_sc_lean ? 1 : 0);
            sc_app(note, nl, ncap, " trapmask=0x");
            sc_app_hex(note, nl, ncap, g_sc_trap_mask);
            sc_app(note, nl, ncap, " maps_real=");
            sc_app_dec(note, nl, ncap, g_sc_maps_real ? 1 : 0);
            sc_app(note, nl, ncap, "\n");
            note[nl] = 0;
            ssize_t u = write(g_sc_log_fd, note, nl);
            (void)u;
        }
    }

    // The supervisor thread starts BEFORE any filter exists, so
    // its own creation cannot be trapped; it waits for the mode.
    g_sc_mode = 0;
    {
        pthread_t th;
        if (pthread_create(&th, nullptr, sc_supervisor_thread,
                           nullptr) == 0) {
            pthread_detach(th);
        }
    }
    long lfd = sc_install_filter_ex(true);
    if (lfd < 0) {
        // Retry without TSYNC (covers the calling thread and all
        // threads created afterwards, which includes the guest's).
        lfd = sc_install_filter_ex(true, true, false);
    }
    if (lfd >= 0) {
        g_sc_listener_fd = static_cast<int>(lfd);
        g_sc_armed = 1;
        g_sc_mode = 1;
        LOGI("seccomp-diag: armed (USER_NOTIF), log=%s modules=%d",
             log_path, g_sc_module_count);
        return 0;
    }
    // Fallback: RET_TRAP + SIGSYS handler, WITHOUT the signal
    // numbers (trapping rt_sigprocmask kills newborn threads whose
    // start path restores the signal mask while SIGSYS is blocked).
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sc_handle;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, &g_sc_prev_action);
    if (sc_install_filter_ex(false, false) != 0) {
        g_sc_mode = 3;
        return -1;
    }
    g_sc_armed = 1;
    g_sc_mode = 2;
    LOGI("seccomp-diag: armed (TRAP fallback), log=%s modules=%d",
         log_path, g_sc_module_count);
    return 0;
#endif
}

}  // namespace

/**
 * Arm the seccomp raw-syscall diagnostic in this (guest stub)
 * process. MUST match Kotlin: nativeArmSeccompDiag(logPath: String)
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeArmSeccompDiag(
    JNIEnv* env, jobject thiz, jstring logPath)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(logPath, nullptr);
    if (p) {
        int rc = sc_arm(p);
        LOGI("seccomp-diag: arm rc=%d", rc);
        env->ReleaseStringUTFChars(logPath, p);
    }
}

/**
 * Override a system property at native level.
 * MUST match Kotlin: nativeSpoofSystemProperty(key: String, value: String)
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSpoofSystemProperty(
    JNIEnv* env, jobject thiz, jstring key, jstring value)
{
    (void)thiz;
    const char* k = env->GetStringUTFChars(key, nullptr);
    const char* v = env->GetStringUTFChars(value, nullptr);

    if (k && v) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_property_spoofs[std::string(k)] = std::string(v);
        LOGI("Property spoof set: %s -> %s", k, v);
    }

    if (k) env->ReleaseStringUTFChars(key, k);
    if (v) env->ReleaseStringUTFChars(value, v);
}

/**
 * Hide a path at native level (return ENOENT on access).
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeHidePath(
    JNIEnv* env, jobject thiz, jstring path)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_hidden_paths.insert(std::string(p));
        LOGD("Path hidden: %s", p);
        env->ReleaseStringUTFChars(path, p);
    }
}

/**
 * Unhide a path at native level.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeUnhidePath(
    JNIEnv* env, jobject thiz, jstring path)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(path, nullptr);
    if (p) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_hidden_paths.erase(std::string(p));
        LOGD("Path unhidden: %s", p);
        env->ReleaseStringUTFChars(path, p);
    }
}

/**
 * Clean up all native hooks and state.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeCleanup(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_path_redirects.clear();
    g_property_spoofs.clear();
    g_hidden_paths.clear();
    g_spoofed_pid = -1;
    g_spoofed_package_name.clear();
    g_host_data_prefix.clear();
    g_virtual_data_root.clear();
    // Note: GOT patches remain in place but do nothing without redirect rules
    LOGI("Native hook state cleaned up");
}

/**
 * Set the host data directory prefix.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetHostDataPrefix(
    JNIEnv* env, jobject thiz, jstring prefix)
{
    (void)thiz;
    const char* p = env->GetStringUTFChars(prefix, nullptr);
    if (p) {
        g_host_data_prefix = std::string(p);
        env->ReleaseStringUTFChars(prefix, p);
        LOGI("Host data prefix: %s", g_host_data_prefix.c_str());
    }
}

/**
 * Set the virtual data root directory.
 */
JNIEXPORT void JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeSetVirtualDataRoot(
    JNIEnv* env, jobject thiz, jstring root)
{
    (void)thiz;
    const char* r = env->GetStringUTFChars(root, nullptr);
    if (r) {
        g_virtual_data_root = std::string(r);
        env->ReleaseStringUTFChars(root, r);
        LOGI("Virtual data root: %s", g_virtual_data_root.c_str());
    }
}

/**
 * Get the current redirect count (for debugging).
 */
JNIEXPORT jint JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeGetRedirectCount(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return static_cast<jint>(g_path_redirects.size());
}

/**
 * Get the current property spoof count (for debugging).
 */
JNIEXPORT jint JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeGetPropertySpoofCount(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return static_cast<jint>(g_property_spoofs.size());
}

/**
 * Check if the native engine is initialized.
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeIsInitialized(
    JNIEnv* env, jobject thiz)
{
    (void)env; (void)thiz;
    return g_initialized ? JNI_TRUE : JNI_FALSE;
}

// ==================== Runtime.nativeLoad Hook ====================
//
// Jiagu/360-protected apps call Runtime.load0() which delegates to
// Runtime.nativeLoad(String filename, ClassLoader loader, Class caller).
// In the virtual environment, the "caller" Class argument becomes null
// because Jiagu's native code calls System.loadLibrary via JNI reflection
// from a thread where the caller class cannot be resolved.
//
// ART's CheckJNI mode then calls GetObjectArrayElement on NULL (the
// ProtectionDomain array derived from the null caller) → SIGABRT.
//
// Fix: Hook Runtime.nativeLoad at JNI registration level via RegisterNatives.
// If caller==null, synthesize a non-null Class from the classLoader or use
// java.lang.Runtime as a fallback caller.

// Original native implementation saved via method registration replacement
static void* g_orig_nativeLoad_fn = nullptr;

// Type alias matching ART's native signature for Runtime.nativeLoad
// static jni: (JNIEnv*, jclass, jstring filename, jobject classLoader, jclass caller) -> jstring
typedef jstring (*NativeLoadFn)(JNIEnv*, jclass, jstring, jobject, jclass);

static jstring hooked_nativeLoad(JNIEnv* env, jclass runtimeClass,
                                  jstring filename, jobject classLoader, jclass caller) {
    if (caller == nullptr) {
        LOGI("Runtime.nativeLoad intercepted with null caller — fixing");

        // Strategy 1: Derive a class from the classLoader
        if (classLoader != nullptr) {
            // Try ClassLoader.loadClass("java.lang.Object") to get a valid Class
            jclass clsLoaderClass = env->GetObjectClass(classLoader);
            if (clsLoaderClass != nullptr) {
                jmethodID loadClassMethod = env->GetMethodID(
                    clsLoaderClass, "loadClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;");
                if (loadClassMethod != nullptr) {
                    jstring objClassName = env->NewStringUTF("java.lang.Object");
                    if (objClassName != nullptr) {
                        // Clear any pending exception before calling loadClass
                        if (env->ExceptionCheck()) env->ExceptionClear();

                        jobject loadedClass = env->CallObjectMethod(
                            classLoader, loadClassMethod, objClassName);
                        env->DeleteLocalRef(objClassName);

                        if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        } else if (loadedClass != nullptr) {
                            caller = static_cast<jclass>(loadedClass);
                            LOGI("Runtime.nativeLoad: fixed null caller via classLoader → java.lang.Object");
                        }
                    }
                }
                env->DeleteLocalRef(clsLoaderClass);
            }
        }

        // Strategy 2: Fallback — use java.lang.Runtime itself as the caller
        if (caller == nullptr) {
            caller = runtimeClass;
            LOGI("Runtime.nativeLoad: fixed null caller → java.lang.Runtime (fallback)");
        }
    }

    // Call original implementation
    if (g_orig_nativeLoad_fn != nullptr) {
        jstring result = ((NativeLoadFn)g_orig_nativeLoad_fn)(
            env, runtimeClass, filename, classLoader, caller);
        // The load may have brought new libraries into the process
        // (e.g. a packer shell's libDexHelper.so via System.loadLibrary
        // in the guest Application's attach). Patch their GOTs now —
        // before any of their JNI methods get invoked.
        patch_newly_loaded_libraries();
        return result;
    }

    // If we somehow don't have the original, try dlsym as last resort
    LOGE("Runtime.nativeLoad: no original function pointer — cannot forward call");
    return nullptr;
}

/**
 * Install the Runtime.nativeLoad hook using RegisterNatives.
 *
 * Approach:
 * 1. Find java.lang.Runtime class
 * 2. Save original nativeLoad function pointer via GetMethodID + JNI internal lookup
 * 3. Register our hooked version via RegisterNatives
 */
static bool installNativeLoadHook(JNIEnv* env) {
    // Find java.lang.Runtime
    jclass runtimeClass = env->FindClass("java/lang/Runtime");
    if (runtimeClass == nullptr) {
        LOGE("installNativeLoadHook: cannot find java/lang/Runtime");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    // Try to get the original native function pointer from libart.so
    // The symbol name varies by ART version but we try the common ones
    void* libart = dlopen("libart.so", RTLD_NOLOAD);
    if (libart == nullptr) {
        LOGW("installNativeLoadHook: libart.so not found via RTLD_NOLOAD, trying dlopen");
        libart = dlopen("libart.so", RTLD_NOW);
    }

    if (libart != nullptr) {
        // ART internal symbol for Runtime_nativeLoad (static JNI method)
        // Try multiple symbol names as it varies across Android versions
        const char* symbols[] = {
            "_ZN3artL18Runtime_nativeLoadEP7_JNIEnvP7_jclassP8_jstringP8_jobjectS5_",
            "Runtime_nativeLoad",
            nullptr
        };

        for (int i = 0; symbols[i] != nullptr; i++) {
            g_orig_nativeLoad_fn = dlsym(libart, symbols[i]);
            if (g_orig_nativeLoad_fn != nullptr) {
                LOGI("installNativeLoadHook: found original at symbol '%s'", symbols[i]);
                break;
            }
        }
    }

    if (g_orig_nativeLoad_fn == nullptr) {
        // Fallback: use env->GetMethodID to verify the method exists,
        // then rely on RegisterNatives to stash the original internally.
        // We'll use a JNI trick: register, then we ARE the native now.
        // To call original, we need the old function pointer.
        // Without it, we try a different approach — call doLoad on Runtime directly.

        // Try using JNI GetStaticMethodID to verify method exists
        jmethodID nativeLoadMethod = env->GetStaticMethodID(
            runtimeClass, "nativeLoad",
            "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;");
        if (nativeLoadMethod == nullptr) {
            LOGE("installNativeLoadHook: Runtime.nativeLoad method not found");
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(runtimeClass);
            return false;
        }

        // Without the original symbol, we can still hook but won't be able to forward.
        // Use a wrapper approach: save the method ID and call via JNI CallStatic
        // But this would recursively call our hook... So we MUST have the original.
        LOGE("installNativeLoadHook: cannot find original native symbol in libart.so");
        env->DeleteLocalRef(runtimeClass);
        return false;
    }

    // Register our hooked version
    JNINativeMethod methods[] = {
        {
            const_cast<char*>("nativeLoad"),
            const_cast<char*>("(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/Class;)Ljava/lang/String;"),
            reinterpret_cast<void*>(hooked_nativeLoad)
        }
    };

    jint result = env->RegisterNatives(runtimeClass, methods, 1);
    env->DeleteLocalRef(runtimeClass);

    if (result != JNI_OK) {
        LOGE("installNativeLoadHook: RegisterNatives failed with code %d", result);
        g_orig_nativeLoad_fn = nullptr;
        return false;
    }

    LOGI("installNativeLoadHook: SUCCESS — Runtime.nativeLoad hooked via RegisterNatives");
    return true;
}

/**
 * JNI bridge for NativeHookBridge.nativeInstallRuntimeLoadHook()
 */
JNIEXPORT jboolean JNICALL
Java_com_nextvm_core_hook_NativeHookBridge_nativeInstallRuntimeLoadHook(
    JNIEnv* env, jobject thiz)
{
    (void)thiz;
    return installNativeLoadHook(env) ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
