package dev.rinusho.hikari.proxy

import java.util.ArrayDeque
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Pre-opened WebSocket connections to Telegram DCs (port of proxy/pool.py `_WsPool`).
 * Connections are dialled to a fixed DC IP while the Host/SNI is `kws{dc}.web.telegram.org`;
 * if that fails, SNI fronting (`sprinthost.ru`) is tried.
 */
class WsPool(private val cfg: ProxyConfig, private val scope: CoroutineScope) {
    private data class Key(val dc: Int, val media: Boolean, val test: Boolean)

    private val lock = Any()
    private val idle = HashMap<Key, ArrayDeque<RawWebSocket>>()
    private val refilling = HashSet<Key>()
    private val failures = HashMap<Key, Int>()
    private val retryAfter = HashMap<Key, Long>()
    @Volatile private var frontingFirst = false
    private var maintenance: Job? = null

    fun start() {
        maintenance = scope.launch {
            while (isActive) {
                delay(CHECK_INTERVAL_MS)
                val keys = synchronized(lock) { idle.keys.toList() }
                for (k in keys) {
                    synchronized(lock) { dropStale(k) }.forEach { scope.launch { it.close() } }
                    scheduleRefill(k)
                }
            }
        }
        for (dc in cfg.dcRedirects.keys) for (media in listOf(false, true)) {
            val k = Key(dc, media, cfg.forceTestDc)
            synchronized(lock) { idle.getOrPut(k) { ArrayDeque() } }
            scheduleRefill(k)
        }
        ProxyLog.i("WS pool warm-up for ${cfg.dcRedirects.size} DC(s)")
    }

    /** Returns a ready WebSocket for the DC or null if none is available. */
    fun get(dc: Int, media: Boolean, test: Boolean = false): RawWebSocket? {
        if (cfg.poolSize <= 0 || cfg.dcRedirects[dc] == null) return null
        val k = Key(dc, media, test)
        var found: RawWebSocket? = null
        val stale: List<RawWebSocket>
        synchronized(lock) {
            stale = dropStale(k)
            found = idle[k]?.pollFirst()
        }
        stale.forEach { scope.launch { it.close() } }
        if (found != null) ProxyStats.poolHits.incrementAndGet() else ProxyStats.poolMisses.incrementAndGet()
        scheduleRefill(k)
        return found
    }

    private fun dropStale(k: Key): List<RawWebSocket> {
        val bucket = idle.getOrPut(k) { ArrayDeque() }
        val now = System.nanoTime()
        val out = ArrayList<RawWebSocket>()
        val it = bucket.iterator()
        while (it.hasNext()) {
            val ws = it.next()
            if (ws.isDead || now - ws.createdAt >= MAX_AGE_NS) {
                it.remove()
                out += ws
            }
        }
        return out
    }

    private fun scheduleRefill(k: Key) {
        val ip = cfg.dcRedirects[k.dc] ?: return
        if (cfg.poolSize <= 0) return
        synchronized(lock) {
            if (k in refilling || System.nanoTime() < (retryAfter[k] ?: 0L)) return
            refilling += k
        }
        scope.launch {
            try {
                val needed = synchronized(lock) { cfg.poolSize - (idle[k]?.size ?: 0) }
                if (needed <= 0) return@launch
                val path = if (k.test) Proto.WS_PATH_TEST else Proto.WS_PATH
                val results = (1..needed).map { async { connectOne(ip, Proto.wsDomains(k.dc, k.media), path) } }.awaitAll()
                val ok = results.filterNotNull()
                synchronized(lock) {
                    val bucket = idle.getOrPut(k) { ArrayDeque() }
                    ok.forEach { bucket.addLast(it) }
                    if (ok.isNotEmpty()) {
                        failures.remove(k); retryAfter.remove(k)
                    } else {
                        val f = (failures[k] ?: 0) + 1
                        failures[k] = f
                        val delaySec = minOf(1L shl minOf(f - 1, 12), 3600L)
                        retryAfter[k] = System.nanoTime() + delaySec * 1_000_000_000L
                        ProxyLog.w("WS pool refill failed for DC${k.dc}${if (k.media) "m" else ""}, retry in ${delaySec}s")
                    }
                }
            } finally {
                synchronized(lock) { refilling -= k }
            }
        }
    }

    private fun connectOne(ip: String, domains: List<String>, path: String): RawWebSocket? {
        for (domain in domains) {
            val modes = if (frontingFirst) listOf(true, false) else listOf(false, true)
            for (fronted in modes) {
                try {
                    val ws = RawWebSocket.connect(
                        ip, domain, timeoutMs = if (fronted) 7000 else 8000, path = path,
                        sni = if (fronted) "sprinthost.ru" else null,
                    )
                    frontingFirst = fronted
                    ProxyLog.d("WS pool connected $domain via $ip (fronting=$fronted)")
                    return ws
                } catch (e: Exception) {
                    ProxyLog.d("WS pool connect $domain via $ip (fronting=$fronted): $e")
                }
            }
        }
        return null
    }

    fun close() {
        maintenance?.cancel()
        val all = synchronized(lock) {
            idle.values.flatMap { it.toList() }.also { idle.clear() }
        }
        all.forEach { runCatching { it.close() } }
    }

    private companion object {
        const val MAX_AGE_NS = 120_000_000_000L
        const val CHECK_INTERVAL_MS = 5_000L
    }
}
