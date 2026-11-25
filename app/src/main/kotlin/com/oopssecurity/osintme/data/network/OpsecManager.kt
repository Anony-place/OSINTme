package com.oopssecurity.osintme.data.network

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetSocketAddress
import java.net.Proxy

enum class ProxyMode(val label: String, val defaultHost: String, val defaultPort: Int) {
    DIRECT("Direct Network Connection", "", 0),
    TOR_ORBOT_SOCKS5("Tor (Orbot SOCKS5 Proxy)", "127.0.0.1", 9050),
    TOR_ORBOT_HTTP("Tor (Orbot HTTP Proxy)", "127.0.0.1", 8118),
    CUSTOM_SOCKS5("Custom SOCKS5 Proxy", "127.0.0.1", 1080),
    CUSTOM_HTTP("Custom HTTP Proxy", "127.0.0.1", 8080)
}

object OpsecManager {

    private const val PREFS_NAME = "osintme_opsec_config"
    private const val KEY_PROXY_MODE = "opsec_proxy_mode"
    private const val KEY_CUSTOM_HOST = "opsec_custom_host"
    private const val KEY_CUSTOM_PORT = "opsec_custom_port"
    private const val KEY_RANDOM_UA = "opsec_random_ua"
    private const val KEY_ANTI_TRACKING = "opsec_anti_tracking"
    private const val KEY_SCREEN_SHIELD = "opsec_screen_shield"

    private val REALISTIC_USER_AGENTS = listOf(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
    )

    private var prefs: SharedPreferences? = null

    private val _screenShieldEnabledFlow = MutableStateFlow(false)
    val screenShieldEnabledFlow: StateFlow<Boolean> = _screenShieldEnabledFlow.asStateFlow()

    fun init(context: Context) {
        if (prefs == null) {
            prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
        _screenShieldEnabledFlow.value = prefs?.getBoolean(KEY_SCREEN_SHIELD, false) ?: false
    }

    var currentProxyMode: ProxyMode
        get() {
            val name = prefs?.getString(KEY_PROXY_MODE, ProxyMode.DIRECT.name) ?: ProxyMode.DIRECT.name
            return try { ProxyMode.valueOf(name) } catch (e: Exception) { ProxyMode.DIRECT }
        }
        set(value) {
            prefs?.edit()?.putString(KEY_PROXY_MODE, value.name)?.apply()
            OsintApiClient.rebuildClient()
        }

    var customHost: String
        get() = prefs?.getString(KEY_CUSTOM_HOST, "127.0.0.1") ?: "127.0.0.1"
        set(value) {
            prefs?.edit()?.putString(KEY_CUSTOM_HOST, value.trim())?.apply()
            OsintApiClient.rebuildClient()
        }

    var customPort: Int
        get() = prefs?.getInt(KEY_CUSTOM_PORT, 9050) ?: 9050
        set(value) {
            prefs?.edit()?.putInt(KEY_CUSTOM_PORT, value.coerceIn(1, 65535))?.apply()
            OsintApiClient.rebuildClient()
        }

    var randomizeUserAgent: Boolean
        get() = prefs?.getBoolean(KEY_RANDOM_UA, true) ?: true
        set(value) {
            prefs?.edit()?.putBoolean(KEY_RANDOM_UA, value)?.apply()
        }

    var antiTrackingHeaders: Boolean
        get() = prefs?.getBoolean(KEY_ANTI_TRACKING, true) ?: true
        set(value) {
            prefs?.edit()?.putBoolean(KEY_ANTI_TRACKING, value)?.apply()
        }

    var screenShieldEnabled: Boolean
        get() = prefs?.getBoolean(KEY_SCREEN_SHIELD, false) ?: false
        set(value) {
            prefs?.edit()?.putBoolean(KEY_SCREEN_SHIELD, value)?.apply()
            _screenShieldEnabledFlow.value = value
        }

    fun getActiveProxy(): Proxy? {
        val mode = currentProxyMode
        return when (mode) {
            ProxyMode.DIRECT -> null
            ProxyMode.TOR_ORBOT_SOCKS5 -> {
                Proxy(Proxy.Type.SOCKS, InetSocketAddress(mode.defaultHost, mode.defaultPort))
            }
            ProxyMode.TOR_ORBOT_HTTP -> {
                Proxy(Proxy.Type.HTTP, InetSocketAddress(mode.defaultHost, mode.defaultPort))
            }
            ProxyMode.CUSTOM_SOCKS5 -> {
                Proxy(Proxy.Type.SOCKS, InetSocketAddress(customHost, customPort))
            }
            ProxyMode.CUSTOM_HTTP -> {
                Proxy(Proxy.Type.HTTP, InetSocketAddress(customHost, customPort))
            }
        }
    }

    fun getRandomUserAgent(): String {
        return REALISTIC_USER_AGENTS.random()
    }

    fun getActiveConfigSummary(): String {
        return when (val mode = currentProxyMode) {
            ProxyMode.DIRECT -> "Direct TLS"
            ProxyMode.TOR_ORBOT_SOCKS5 -> "Tor SOCKS5 (${mode.defaultHost}:${mode.defaultPort})"
            ProxyMode.TOR_ORBOT_HTTP -> "Tor HTTP (${mode.defaultHost}:${mode.defaultPort})"
            ProxyMode.CUSTOM_SOCKS5 -> "SOCKS5 ($customHost:$customPort)"
            ProxyMode.CUSTOM_HTTP -> "HTTP Proxy ($customHost:$customPort)"
        }
    }
}
