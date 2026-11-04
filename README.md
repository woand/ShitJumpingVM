# ShitJumpingVM

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android-3DDC84?style=for-the-badge&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/Language-Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" />
  <img src="https://img.shields.io/badge/NDK-C++-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" />
  <img src="https://img.shields.io/badge/Min%20SDK-26-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Target%20SDK-35-blue?style=for-the-badge" />
</p>

<p align="center">
  <strong>A no-root, user-space Android virtualization engine: run a guest APK inside
  an isolated sandbox process of a host app, on the phone itself.</strong>
</p>

<p align="center">
  <a href="#what-it-is">What it is</a> &bull;
  <a href="#how-it-works">How it works</a> &bull;
  <a href="#module-structure">Module structure</a> &bull;
  <a href="#status">Status</a> &bull;
  <a href="#building">Building</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#license">License</a>
</p>

---

## What it is

ShitJumpingVM is a fork and rename of NEXTVM. It does not emulate hardware and
does not modify the OS. A guest app runs as an ordinary app process, but its
Binder IPC, activity launches, class loading, and file paths are intercepted
and redirected into a per-instance sandbox, so the guest sees its own data
directory, files, and storage instead of the host's.

The project is experimental and under active development
(`versionName 1.0.0-alpha01`). It is aimed at app-compatibility work and
controlled runtime diagnostics: getting real apps to boot and run inside the
sandbox, and finding out exactly where they diverge from running normally.

> Note on naming: the repository and project are now ShitJumpingVM, but the
> host app's `applicationId` / namespace is still `com.nextvm.app` — renaming
> it was not part of the fork, so you will still see `com.nextvm` in code,
> package names, and on-device paths.

---

## How it works

```
Guest APK
    │  installed into the sandbox (files/virtual/apks/<instance>.apk)
    ▼
Host app (com.nextvm.app)
    │  VirtualEngine boots the guest: classloader, VirtualContext,
    │  resources, ContentProviders, Binder proxies
    ▼
Stub components (manifest-declared, 10 process slots P0–P9)
    │  startActivity/startService/bindService calls are rewritten
    │  to a stub; ActivityThreadHook swaps the real guest class in
    │  at launch time (EXECUTE_TRANSACTION interception)
    ▼
Guest Application / Activity running in a :pN stub process
    │  file I/O goes through VirtualContext + native GOT/PLT hooks
    │  and lands in files/virtual/data/<instance>/
    ▼
Android OS (unmodified, no root)
```

### The interception layers

1. **Binder proxies** (`core/binder`) — `IActivityManager`, `IPackageManager`,
   and system-service proxies intercept app-to-system IPC. Guest
   `startActivity` calls are rewritten to a stub component
   (`P<slot>$Standard00` and siblings); intents pass through
   `IntentParcelSanitizer`, which only drops a key when it is proven to
   carry a recycled `Bitmap` — unreadable keys are passed through
   untouched, so guest data is not silently stripped in transit.
2. **ActivityThread hook** (`core/virtualization`) — intercepts
   `EXECUTE_TRANSACTION` to replace the stub classloader and class with
   the guest's own, then instantiates the real guest component. This is
   what makes a manifest-declared stub actually run guest code.
3. **Virtual context and sandbox** (`core/sandbox`) — `VirtualContext`
   redirects files, databases, and preferences into the sandbox layout
   below, and `SandboxManager` owns that layout. The guest's
   `dataDir` / `filesDir` / `cacheDir` live under the host app's files
   directory, and its external-storage root is a simulated sdcard
   inside the sandbox — not the device's real storage.
4. **Native hooks** (`core/hook`, C++) — a GOT/PLT patcher
   (`native-hook.cpp`) redirects libc calls (`open`, `openat`, `access`,
   `stat`, `connect`, `getaddrinfo`, …) for guest processes, enforcing
   path redirection at the native layer and recording failures for
   diagnostics. Hook bodies are deliberately minimal (integer and
   package-name comparisons only, no file I/O inside a hook) so a hook
   cannot recurse through itself.
5. **Class loading** (`core/apk`, `core/framework`) — the framework
   `LoadedApk` for the guest is built from the sandbox APK path, and the
   guest is loaded with the framework's own classloader. The guest's
   `Application` and `Activity` classes therefore come from its own APK,
   not from the host.

### Sandbox layout

```
<host files>/virtual/
├── apks/<instance>.apk                  # guest APK copy
└── data/<instance>/
    ├── files/                           # guest filesDir (incl. guest probes/logs)
    ├── cache/                           # guest cacheDir
    ├── lib/                             # guest nativeLibraryDir
    └── sdcard/                          # simulated external storage root
```

Guest processes are named after their stub slot (`:p0`, `:p2`, …), not
after the guest package, and the guest runs with the host app's UID —
both are visible differences from a normally installed app, and both
matter when diagnosing compatibility problems.

---

## Module structure

15 modules: 1 app + 10 core + 4 feature. Verified against
`settings.gradle.kts`.

```
ShitJumpingVM/
├── app/                          # Host entry: NextVmApplication, MainActivity,
│                                 # stub components (StubComponents.kt), Hilt DI
├── core/
│   ├── virtualization/           # VirtualEngine, ActivityThreadHook, process slots,
│   │                             # guest lifecycle, breadcrumb diagnostics
│   ├── binder/                   # BinderProxyManager, AM/PM/system-service proxies,
│   │                             # intent rewriting (ActivityManagerProxy),
│   │                             # IntentParcelSanitizer
│   ├── sandbox/                  # SandboxManager layout, VirtualContext,
│   │                             # NativeLibManager
│   ├── hook/                     # Native GOT/PLT hooks (C++), NativeHookBridge,
│   │                             # HookEngine, IdentitySpoofingEngine,
│   │                             # AntiDetectionEngine (see Status)
│   ├── apk/                      # ApkParser, VirtualClassLoader
│   ├── framework/                # Framework LoadedApk construction, dex/pkg parsing
│   ├── model/                    # VirtualApp, DeviceProfile, ProcessSlot, ApkInfo
│   ├── services/                 # Virtual AM/PM/component/intent/network/
│   │                             # permission services, GMS scaffolding
│   ├── common/                   # Reflection and compatibility helpers
│   └── designsystem/             # Material 3 theme
├── feature/
│   ├── launcher/                 # Guest app grid (Compose)
│   ├── appmanager/               # Guest install/uninstall management (Compose)
│   ├── settings/                 # Engine configuration and debugging (Compose)
│   └── filemanager/              # Sandbox filesystem browser (Compose)
└── gradle/                       # Version catalog
```

### Stub components

160 manifest-declared stub components in total, across 10 process slots:

| Slots | Per slot | Components |
|-------|----------|------------|
| P0–P4 | 20 | 10 Activities (5 Standard, 2 SingleTop, 2 SingleTask, 1 SingleInstance), 5 Services, 3 ContentProviders, 2 Receivers |
| P5–P9 | 12 | 6 Activities, 3 Services, 2 ContentProviders, 1 Receiver |

Totals: 80 Activities, 40 Services, 25 ContentProviders, 15 Receivers.
(The old README's "200 components, 10 × 20" was wrong.)

---

## Status

### What works

- Guest APK installation into the sandbox and launch into a stub process
- Per-instance sandbox directories, with Java-layer file redirection
- Guest `ContentProvider` installation during boot
- Activity navigation through stub rewriting (including the
  `DELIVERED_TO_TOP` re-send to a different Standard slot as a safety net)
- Compose UI: launcher, app manager, settings, sandbox file browser
- File-based diagnostics (per-process breadcrumb logs, intent-probe logs,
  native connect/DNS failure logs) — logcat is unreliable for guest
  processes on the devices used here, so durable files are the channel
  diagnostics actually rely on

### What is partial or not yet built

- **Identity spoofing is not applied.** `IdentitySpoofingEngine` and
  `DeviceProfile` exist in code, but no profile is applied in the current
  boot path, and the system-service proxies currently pass real values
  through (their virtual-call gate is never satisfied). Do not describe
  this project as spoofing device identity — that is a direction, not a
  working feature.
- **No Java/ART method-hook infrastructure.** `HookEngine` lists LSPlant
  (ART hooks) and Dobby (inline hooks) as future work. The native layer
  is GOT/PLT patching only, and `libart.so` is explicitly never patched,
  so ART's own dex opening bypasses the file hooks — a known limit when
  reasoning about class-loading behavior.
- **Guest compatibility varies by app.** Apps with packers or strong
  integrity checks are the hardest cases; a guest that boots to its main
  UI is not a guarantee that every feature (login, WebView, payments,
  media, face verification, …) works inside the sandbox. Each guest and
  each feature has to be verified on its own.
- **No test suite.** Test coverage is thin; contributions of tests are
  welcome (see Contributing).

### Directions, not promises

- Wiring up identity profiles behind the existing engine code
- ART method-hook infrastructure, so app-layer callbacks can be observed
  instead of only native calls
- Broader guest compatibility, verified one app and one feature at a time
- Documentation that stays in step with the code (this file included)

---

## Building

### Prerequisites

- JDK 17
- Android SDK 35
- NDK 27.1.12297006
- CMake (for the `core/hook` native module)
- Gradle 8.9 (via the wrapper)

### Steps

```bash
# Clone the repository
git clone https://github.com/woand/ShitJumpingVM.git
cd ShitJumpingVM

# Build debug APK
./gradlew :app:assembleDebug

# Install on a connected device
./gradlew :app:installDebug
```

The host app is a debug build signed with the project's debug keystore;
`minSdk 26`, `targetSdk 35`, Kotlin 2.0.21, Compose BOM 2024.12.01,
Hilt 2.53.1.

> Note: ShitJumpingVM is a fork of NEXTVM
> (upstream: `https://github.com/TanvirHossain2/NEXTVM`). The original
> NEXTVM README's feature lists, roadmap, and comparison tables were
> aspirational and did not match this codebase; they were removed in this
> rewrite rather than carried over.

---

## Contributing

Contributions are welcome — this is a systems-level codebase, and the
fastest way in is to read the interception path end to end:

1. `core/virtualization` → `VirtualEngine` (boot) and
   `ActivityThreadHook` (launch interception)
2. `core/binder` → `ActivityManagerProxy` (intent rewriting) and
   `IntentParcelSanitizer` (parcel safety)
3. `core/sandbox` → `SandboxManager` and `VirtualContext`
4. `core/hook/src/main/cpp/native-hook.cpp` → the GOT/PLT patcher
5. `core/model` → `VirtualApp`, `ProcessSlot`, `DeviceProfile`

Good first contributions: tests for core modules, error handling and
logging, UI polish, and documentation fixes. For compatibility work,
please verify on a real device and report exactly what was observed
(process alive, UI rendered, navigation completed, input usable) rather
than what was expected.

To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear commit messages
4. Submit a pull request describing what changed and why

---

## Disclaimer

ShitJumpingVM is built for legitimate compatibility and diagnostics work:
running apps in isolation, testing them across configurations, and
analyzing runtime behavior in a controlled environment. Users are
responsible for complying with applicable laws and with the terms of
service of any app they run inside it.

---

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for the full
text.
