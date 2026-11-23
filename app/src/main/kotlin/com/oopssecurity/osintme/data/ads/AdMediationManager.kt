package com.oopssecurity.osintme.data.ads

import android.app.Activity
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object AdMediationManager {
    // AppLovin MAX / LevelPlay configuration keys
    var sdkKey: String = "APPLOVIN_MAX_TEST_SDK_KEY"
    var bannerUnitId: String = "test_banner_unit"
    var interstitialUnitId: String = "test_interstitial_unit"
    var rewardedUnitId: String = "test_rewarded_unit"

    private var scanCountSinceLastAd = 0
    private var lastInterstitialTimeMs = 0L
    private const val INTERSTITIAL_COOLDOWN_MS = 3 * 60 * 1000L // 3 minutes strict cooldown
    private const val MIN_SCANS_BEFORE_INTERSTITIAL = 3

    // Deep Scan unlock state (unlocked by rewarded video)
    private val _deepScanUnlocked = MutableStateFlow(false)
    val deepScanUnlocked: StateFlow<Boolean> = _deepScanUnlocked.asStateFlow()

    fun recordCompletedScan(activity: Activity? = null) {
        scanCountSinceLastAd++
        if (canShowInterstitial()) {
            showInterstitial(activity)
        }
    }

    fun canShowInterstitial(): Boolean {
        val elapsed = System.currentTimeMillis() - lastInterstitialTimeMs
        return scanCountSinceLastAd >= MIN_SCANS_BEFORE_INTERSTITIAL && elapsed >= INTERSTITIAL_COOLDOWN_MS
    }

    fun showInterstitial(activity: Activity?) {
        if (!canShowInterstitial()) return

        // Controlled interstitial presentation
        lastInterstitialTimeMs = System.currentTimeMillis()
        scanCountSinceLastAd = 0
        // In production AppLovin MAX, MaxInterstitialAd.showAd() is invoked here.
    }

    /**
     * Top 15 username checks are free; watching a rewarded video unlocks all 35+ Deep Scan.
     */
    fun showRewardedVideo(activity: Activity?, onRewardGranted: () -> Unit) {
        // In production, MaxRewardedAd.showAd() with OnAdRevenuePaid / OnUserRewardedListener
        _deepScanUnlocked.value = true
        onRewardGranted()
    }

    fun unlockDeepScanForSession() {
        _deepScanUnlocked.value = true
    }
}
