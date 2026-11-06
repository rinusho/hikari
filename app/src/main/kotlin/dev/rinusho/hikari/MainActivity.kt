package dev.rinusho.hikari

import android.Manifest
import android.app.Application
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.rinusho.hikari.proxy.ProxyLog
import dev.rinusho.hikari.proxy.ProxyStats
import dev.rinusho.hikari.proxy.randomSecretHex
import dev.rinusho.hikari.ui.TgWsApp
import dev.rinusho.hikari.ui.TgWsTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = SettingsRepo(app)

    private val _settings = MutableStateFlow(repo.load())
    val settings: StateFlow<Settings> = _settings

    private val _stats = MutableStateFlow(ProxyStats.snapshot())
    val stats: StateFlow<ProxyStats.Snapshot> = _stats

    val running = ProxyState.running
    val error = ProxyState.error
    val runningConfig = ProxyState.runningConfig
    val logs = ProxyLog.lines

    init {
        viewModelScope.launch {
            while (true) {
                _stats.value = ProxyStats.snapshot()
                delay(1000)
            }
        }
    }

    fun update(transform: (Settings) -> Settings) {
        val s = transform(_settings.value)
        _settings.value = s
        repo.save(s)
    }

    fun regenerateSecret() = update { it.copy(secret = randomSecretHex()) }

    fun start() {
        ProxyState.error.value = null
        ProxyService.start(getApplication())
    }

    fun stop() = ProxyService.stop(getApplication())

    fun restart() {
        stop()
        viewModelScope.launch {
            delay(400)
            start()
        }
    }

    fun clearLogs() = ProxyLog.clear()
}

class MainActivity : ComponentActivity() {
    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* the service works either way */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            TgWsTheme {
                val vm: MainViewModel = viewModel()
                TgWsApp(vm)
            }
        }
    }
}
