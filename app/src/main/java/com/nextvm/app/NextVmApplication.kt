package com.nextvm.app

import android.app.Application
import com.nextvm.core.model.VmResult
import com.nextvm.core.virtualization.engine.VirtualEngine
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import timber.log.Timber
import javax.inject.Inject

@HiltAndroidApp
class NextVmApplication : Application() {

    @Inject
    lateinit var engine: VirtualEngine

    // Application-level coroutine scope
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()

        // 1. Initialize logging
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        Timber.i("NEXTVM Application started — Android ${android.os.Build.VERSION.SDK_INT}")

        // 2. CRITICAL: Install ATHook SYNCHRONOUSLY on main thread FIRST!
        //    This MUST happen BEFORE any EXECUTE_TRANSACTION arrives from ActivityThread.
        //    In child processes (:p0, :p1), Android sends EXECUTE_TRANSACTION immediately
        //    after Application.onCreate() returns, so ATHook must be ready by then.
        engine.installActivityThreadHookEarly(this)

        // 2.5 (v44): Wrap the raw "activity" binder in ServiceManager's
        //     cache SYNCHRONOUSLY. launch61 proved guest code reaches
        //     AMS through this raw binder (never through the replaced
        //     singleton), so the wrap must be in place before any
        //     guest code can capture the binder from the cache.
        try {
            engine.installActivityBinderWrapEarly(this)
        } catch (t: Throwable) {
            Timber.e(t, "ActivityBinderWrap install failed")
        }

        // 3. Initialize the rest of the Virtual Engine on a background thread
        //    (remaining steps are heavy — don't block main thread)
        appScope.launch {
            Timber.i("Initializing VirtualEngine...")
            when (val result = engine.initialize()) {
                is VmResult.Success -> {
                    Timber.i("VirtualEngine initialized successfully ✓")
                }
                is VmResult.Error -> {
                    Timber.e(result.exception, "VirtualEngine initialization failed: ${result.message}")
                }
                is VmResult.Loading -> { /* no-op */ }
            }
        }
    }
}
