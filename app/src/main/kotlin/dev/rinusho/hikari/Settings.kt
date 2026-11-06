package dev.rinusho.hikari

import android.content.Context
import dev.rinusho.hikari.proxy.DEFAULT_DC_IPS
import dev.rinusho.hikari.proxy.DEFAULT_PORT
import dev.rinusho.hikari.proxy.ProxyConfig
import dev.rinusho.hikari.proxy.parseDcIps
import dev.rinusho.hikari.proxy.parseDomains
import dev.rinusho.hikari.proxy.randomSecretHex
import kotlinx.coroutines.flow.MutableStateFlow

data class Settings(
    val port: Int = DEFAULT_PORT,
    val secret: String = "",
    val dcIps: String = DEFAULT_DC_IPS,
    val poolSize: Int = 4,
    val cfFallback: Boolean = true,
    val cfDomains: String = "",
) {
    fun toConfig(): Result<ProxyConfig> = parseDcIps(dcIps).map {
        ProxyConfig(
            port = port,
            secretHex = secret,
            dcRedirects = it,
            poolSize = poolSize,
            cfFallback = cfFallback,
            cfUserDomains = parseDomains(cfDomains),
        )
    }
}

class SettingsRepo(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    fun load(): Settings {
        var secret = prefs.getString("secret", null)
        if (secret == null || secret.length != 32) {
            secret = randomSecretHex()
            prefs.edit().putString("secret", secret).apply()
        }
        return Settings(
            port = prefs.getInt("port", DEFAULT_PORT),
            secret = secret,
            dcIps = prefs.getString("dcIps", DEFAULT_DC_IPS) ?: DEFAULT_DC_IPS,
            poolSize = prefs.getInt("poolSize", 4),
            cfFallback = prefs.getBoolean("cfFallback", true),
            cfDomains = prefs.getString("cfDomains", "") ?: "",
        )
    }

    fun save(s: Settings) {
        prefs.edit()
            .putInt("port", s.port).putString("secret", s.secret).putString("dcIps", s.dcIps)
            .putInt("poolSize", s.poolSize).putBoolean("cfFallback", s.cfFallback)
            .putString("cfDomains", s.cfDomains).apply()
    }

    var wantRunning: Boolean
        get() = prefs.getBoolean("wantRunning", false)
        set(v) = prefs.edit().putBoolean("wantRunning", v).apply()
}

/** Process-wide proxy state observed by the UI and written by [ProxyService]. */
object ProxyState {
    val running = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
    val runningConfig = MutableStateFlow<ProxyConfig?>(null)
}
