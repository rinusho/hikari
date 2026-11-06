package dev.rinusho.hikari

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import dev.rinusho.hikari.proxy.ProxyConfig
import dev.rinusho.hikari.proxy.ProxyEngine
import dev.rinusho.hikari.proxy.ProxyLog

class ProxyService : Service() {
    private var engine: ProxyEngine? = null
    private lateinit var repo: SettingsRepo

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        repo = SettingsRepo(this)
        val ch = NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                repo.wantRunning = false
                stopProxy()
                return START_NOT_STICKY
            }
            else -> {
                // Restarted by the system after the process was killed: honour the last user choice.
                if (intent == null && !repo.wantRunning) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                startProxy()
            }
        }
        return START_STICKY
    }

    private fun startProxy() {
        val settings = repo.load()
        // Must be called promptly after startForegroundService(), even if startup then fails.
        startInForeground("127.0.0.1", settings.port)
        val cfg: ProxyConfig = settings.toConfig().getOrElse {
            fail(it.message ?: "invalid settings")
            return
        }
        engine?.stop()
        try {
            val e = ProxyEngine(cfg)
            e.start()
            engine = e
            repo.wantRunning = true
            ProxyState.error.value = null
            ProxyState.runningConfig.value = cfg
            ProxyState.running.value = true
        } catch (t: Exception) {
            fail(getString(R.string.err_bind, cfg.port, t.message ?: t.javaClass.simpleName))
        }
    }

    private fun fail(msg: String) {
        ProxyLog.w(msg)
        ProxyState.error.value = msg
        repo.wantRunning = false
        stopProxy()
    }

    private fun stopProxy() {
        engine?.stop()
        engine = null
        ProxyState.running.value = false
        ProxyState.runningConfig.value = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startInForeground(host: String, port: Int) {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notif_text, host, port))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, getString(R.string.notif_stop), stop)
            .build()
        val type = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        ServiceCompat.startForeground(this, 1, n, type)
    }

    override fun onDestroy() {
        engine?.stop()
        engine = null
        ProxyState.running.value = false
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "proxy"
        const val ACTION_STOP = "dev.rinusho.hikari.STOP"

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, ProxyService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, ProxyService::class.java).setAction(ACTION_STOP))
        }
    }
}
