package com.nextvm.app

import android.content.Context
import com.nextvm.core.binder.proxy.ContentResolverProxy
import com.nextvm.core.binder.proxy.SystemServiceProxyManager
import com.nextvm.core.framework.parsing.FrameworkApkParser
import com.nextvm.core.hook.AntiDetectionEngine
import com.nextvm.core.hook.HookEngine
import com.nextvm.core.hook.IdentitySpoofingEngine
import com.nextvm.core.hook.NativeHookBridge
import com.nextvm.core.sandbox.SandboxManager
import com.nextvm.core.sandbox.VirtualEnvironmentHook
import com.nextvm.core.services.VirtualServiceManager
import com.nextvm.core.services.am.VirtualActivityManagerService
import com.nextvm.core.services.component.VirtualBroadcastManager
import com.nextvm.core.services.component.VirtualContentProviderManager
import com.nextvm.core.services.component.VirtualServiceLifecycleManager
import com.nextvm.core.services.gms.GmsBinderBridge
import com.nextvm.core.services.gms.GmsFcmProxy
import com.nextvm.core.services.gms.GmsPackageIdentitySpoofer
import com.nextvm.core.services.gms.GmsPlayStoreProxy
import com.nextvm.core.services.gms.VirtualAccountManager
import com.nextvm.core.services.gms.VirtualFirebaseAuthProxy
import com.nextvm.core.services.gms.VirtualGmsManager
import com.nextvm.core.services.gms.VirtualGoogleSignInManager
import com.nextvm.core.services.intent.DeepLinkResolver
import com.nextvm.core.services.network.VirtualNetworkManager
import com.nextvm.core.services.permission.VirtualPermissionManager
import com.nextvm.core.services.pm.VirtualPackageManagerService
import com.nextvm.core.virtualization.engine.VirtualEngine
import com.nextvm.core.virtualization.lifecycle.VirtualApplicationManager
import com.nextvm.core.virtualization.lifecycle.VirtualConfigurationManager
import com.nextvm.core.virtualization.lifecycle.VirtualResourceManager
import com.nextvm.core.virtualization.process.VirtualMultiProcessManager
import com.nextvm.core.virtualization.ui.VirtualWindowManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    // ─── Phase 2 Core ───────────────────────────────────────────

    @Provides
    @Singleton
    fun provideFrameworkApkParser(
        @ApplicationContext context: Context
    ): FrameworkApkParser = FrameworkApkParser(context)

    @Provides
    @Singleton
    fun provideVirtualPackageManagerService(): VirtualPackageManagerService =
        VirtualPackageManagerService()

    @Provides
    @Singleton
    fun provideVirtualActivityManagerService(
        vpms: VirtualPackageManagerService
    ): VirtualActivityManagerService = VirtualActivityManagerService(vpms)

    // ─── Application & Component Lifecycle ──────────────────────

    @Provides
    @Singleton
    fun provideVirtualApplicationManager(
        resourceManager: VirtualResourceManager
    ): VirtualApplicationManager =
        VirtualApplicationManager(resourceManager)

    @Provides
    @Singleton
    fun provideVirtualResourceManager(): VirtualResourceManager =
        VirtualResourceManager()

    @Provides
    @Singleton
    fun provideVirtualConfigurationManager(): VirtualConfigurationManager =
        VirtualConfigurationManager()

    @Provides
    @Singleton
    fun provideVirtualServiceLifecycleManager(): VirtualServiceLifecycleManager =
        VirtualServiceLifecycleManager()

    @Provides
    @Singleton
    fun provideVirtualBroadcastManager(): VirtualBroadcastManager =
        VirtualBroadcastManager()

    @Provides
    @Singleton
    fun provideVirtualContentProviderManager(): VirtualContentProviderManager =
        VirtualContentProviderManager()

    // ─── Intent / Permission / Deep Link ────────────────────────

    @Provides
    @Singleton
    fun provideDeepLinkResolver(): DeepLinkResolver =
        DeepLinkResolver()

    @Provides
    @Singleton
    fun provideVirtualPermissionManager(): VirtualPermissionManager =
        VirtualPermissionManager()

    // ─── System Service Proxies ─────────────────────────────────

    @Provides
    @Singleton
    fun provideSystemServiceProxyManager(): SystemServiceProxyManager =
        SystemServiceProxyManager()

    @Provides
    @Singleton
    fun provideContentResolverProxy(): ContentResolverProxy =
        ContentResolverProxy()

    // ─── Hook Engine / Identity / Anti-Detection ────────────────

    @Provides
    @Singleton
    fun provideHookEngine(): HookEngine = HookEngine()

    @Provides
    @Singleton
    fun provideNativeHookBridge(): NativeHookBridge =
        NativeHookBridge()

    @Provides
    @Singleton
    fun provideIdentitySpoofingEngine(
        hookEngine: HookEngine
    ): IdentitySpoofingEngine = IdentitySpoofingEngine(hookEngine)

    @Provides
    @Singleton
    fun provideAntiDetectionEngine(
        hookEngine: HookEngine,
        nativeHookBridge: NativeHookBridge
    ): AntiDetectionEngine = AntiDetectionEngine(hookEngine, nativeHookBridge)

    // ─── Network ──────────────────────────────────────────────

    @Provides
    @Singleton
    fun provideVirtualNetworkManager(): VirtualNetworkManager =
        VirtualNetworkManager()

    // ─── Hybrid GMS (7 components) ──────────────────────────

    @Provides
    @Singleton
    fun provideGmsPackageIdentitySpoofer(): GmsPackageIdentitySpoofer =
        GmsPackageIdentitySpoofer()

    @Provides
    @Singleton
    fun provideGmsBinderBridge(): GmsBinderBridge =
        GmsBinderBridge()

    @Provides
    @Singleton
    fun provideVirtualAccountManager(): VirtualAccountManager =
        VirtualAccountManager()

    @Provides
    @Singleton
    fun provideVirtualGoogleSignInManager(): VirtualGoogleSignInManager =
        VirtualGoogleSignInManager()

    @Provides
    @Singleton
    fun provideVirtualFirebaseAuthProxy(
        googleSignInManager: VirtualGoogleSignInManager
    ): VirtualFirebaseAuthProxy =
        VirtualFirebaseAuthProxy(googleSignInManager)

    @Provides
    @Singleton
    fun provideGmsFcmProxy(): GmsFcmProxy =
        GmsFcmProxy()

    @Provides
    @Singleton
    fun provideGmsPlayStoreProxy(): GmsPlayStoreProxy =
        GmsPlayStoreProxy()

    @Provides
    @Singleton
    fun provideVirtualGmsManager(
        googleSignInManager: VirtualGoogleSignInManager,
        firebaseAuthProxy: VirtualFirebaseAuthProxy,
        binderBridge: GmsBinderBridge,
        accountManager: VirtualAccountManager,
        identitySpoofer: GmsPackageIdentitySpoofer,
        fcmProxy: GmsFcmProxy,
        playStoreProxy: GmsPlayStoreProxy
    ): VirtualGmsManager = VirtualGmsManager(
        googleSignInManager, firebaseAuthProxy, binderBridge,
        accountManager, identitySpoofer, fcmProxy, playStoreProxy
    )

    // ─── Multi-Process / UI / Window ────────────────────────────

    @Provides
    @Singleton
    fun provideVirtualMultiProcessManager(): VirtualMultiProcessManager =
        VirtualMultiProcessManager()

    @Provides
    @Singleton
    fun provideVirtualWindowManager(): VirtualWindowManager =
        VirtualWindowManager()

    // ─── Sandbox / External Storage ──────────────────────────────

    @Provides
    @Singleton
    fun provideSandboxManager(
        @ApplicationContext context: Context
    ): SandboxManager {
        val virtualRoot = context.getDir("virtual", Context.MODE_PRIVATE)
        return SandboxManager(context, virtualRoot)
    }

    @Provides
    @Singleton
    fun provideVirtualEnvironmentHook(
        sandboxManager: SandboxManager
    ): VirtualEnvironmentHook = VirtualEnvironmentHook(sandboxManager)

    // ─── Coordinators ───────────────────────────────────────────

    @Provides
    @Singleton
    fun provideVirtualServiceManager(
        vams: VirtualActivityManagerService,
        vpms: VirtualPackageManagerService,
        serviceLifecycleManager: VirtualServiceLifecycleManager,
        broadcastManager: VirtualBroadcastManager,
        contentProviderManager: VirtualContentProviderManager,
        deepLinkResolver: DeepLinkResolver,
        permissionManager: VirtualPermissionManager,
        networkManager: VirtualNetworkManager,
        gmsManager: VirtualGmsManager
    ): VirtualServiceManager = VirtualServiceManager(
        vams, vpms,
        serviceLifecycleManager, broadcastManager, contentProviderManager,
        deepLinkResolver, permissionManager, networkManager, gmsManager
    )

    @Provides
    @Singleton
    fun provideVirtualEngine(
        @ApplicationContext context: Context,
        frameworkApkParser: FrameworkApkParser,
        serviceManager: VirtualServiceManager,
        applicationManager: VirtualApplicationManager,
        resourceManager: VirtualResourceManager,
        configurationManager: VirtualConfigurationManager,
        systemServiceProxyManager: SystemServiceProxyManager,
        contentResolverProxy: ContentResolverProxy,
        identitySpoofingEngine: IdentitySpoofingEngine,
        nativeHookBridge: NativeHookBridge,
        antiDetectionEngine: AntiDetectionEngine,
        multiProcessManager: VirtualMultiProcessManager,
        windowManager: VirtualWindowManager,
        virtualEnvironmentHook: VirtualEnvironmentHook
    ): VirtualEngine = VirtualEngine(
        context, frameworkApkParser, serviceManager,
        applicationManager, resourceManager, configurationManager,
        systemServiceProxyManager, contentResolverProxy,
        identitySpoofingEngine, nativeHookBridge, antiDetectionEngine,
        multiProcessManager, windowManager, virtualEnvironmentHook
    )
}
