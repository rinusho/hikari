package dev.rinusho.hikari.proxy

import java.util.ArrayDeque
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Warm WebSockets to Cloudflare Worker relays (port of proxy/pool.py `_CfWorkerPool`).
 * A Worker lives at `wss://<worker>/apiws?dst=<telegram ip>&dc=<n>` and forwards to Telegram's TCP port.
 * One idle connection per DC is kept for DCs that are not served by a direct WebSocket.
 */
class CfWorkerPool(private val cfg: ProxyConfig, private val scope: CoroutineScope) {
    private class Entry(val ws: RawWebSocket, val domain: String)

    private val lock = Any()
    private val idle = HashMap<Int, ArrayDeque<Entry>>()
    private val refilling = HashSet<Int>()
    private val failures = HashMap<Int, Int>()
    private val retryAfter = HashMap<Int, Long>()
    private var maintenance: Job? = null

    private val enabled get() = cfg.poolSize > 0 && cfg.cfWorkerDomains.isNotEmpty()

    fun start() {
        if (!enabled) return
        val targets = Proto.DC_DEFAULT_IPS.filterKeys { it !in cfg.dcRedirects }
        for ((dc, ip) in targets) refill(dc, ip)
        ProxyLog.i("CF worker pool warm-up for ${targets.size} DC(s)")
        maintenance = scope.launch {
            while (isActive) {
                delay(CHECK_INTERVAL_MS)
                for ((dc, ip) in targets) {
                    val stale = synchronized(lock) { dropStale(dc) }
                    stale.forEach { scope.launch { it.ws.close() } }
                    refill(dc, ip)
                }
            }
        }
    }

    fun connectPath(dc: Int, dst: String) = "${Proto.WS_PATH}?dst=$dst&dc=$dc"

    /** Returns a pooled connection and the worker domain it belongs to, or null on a miss. */
    fun get(dc: Int, dst: String): Pair<RawWebSocket, String>? {
        if (!enabled) return null
        val entry: Entry?
        val stale: List<Entry>
        synchronized(lock) {
            stale = dropStale(dc)
            entry = idle[dc]?.pollFirst()
        }
        stale.forEach { scope.launch { it.ws.close() } }
        refill(dc, dst)
        return entry?.let { it.ws to it.domain }
    }

    /** Opens a new Worker connection right now (random domain order). */
    fun connectNow(dc: Int, dst: String, timeoutMs: Int): Pair<RawWebSocket, String>? {
        for (domain in cfg.cfWorkerDomains.distinct().shuffled()) {
            try {
                val ws = RawWebSocket.connect(
                    domain, domain, timeoutMs = timeoutMs, path = connectPath(dc, dst), secure = !cfg.disableSecure,
                )
                return ws to domain
            } catch (e: Exception) {
                ProxyLog.w("CF worker $domain failed: ${e.javaClass.simpleName}")
            }
        }
        return null
    }

    private fun dropStale(dc: Int): List<Entry> {
        val bucket = idle.getOrPut(dc) { ArrayDeque() }
        val now = System.nanoTime()
        val out = ArrayList<Entry>()
        val it = bucket.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (e.ws.isDead || now - e.ws.createdAt >= MAX_AGE_NS) { it.remove(); out += e }
        }
        return out
    }

    private fun refill(dc: Int, dst: String) {
        if (!enabled) return
        synchronized(lock) {
            if (dc in refilling || System.nanoTime() < (retryAfter[dc] ?: 0L)) return
            if ((idle[dc]?.size ?: 0) >= PER_DC_LIMIT) return
            refilling += dc
        }
        scope.launch {
            try {
                val made = connectNow(dc, dst, 8000)
                synchronized(lock) {
                    if (made != null) {
                        idle.getOrPut(dc) { ArrayDeque() }.addLast(Entry(made.first, made.second))
                        failures.remove(dc); retryAfter.remove(dc)
                    } else {
                        val f = (failures[dc] ?: 0) + 1
                        failures[dc] = f
                        val delaySec = minOf(1L shl minOf(f - 1, 12), 3600L)
                        retryAfter[dc] = System.nanoTime() + delaySec * 1_000_000_000L
                        ProxyLog.w("CF worker pool refill failed for DC$dc, retry in ${delaySec}s")
                    }
                }
            } finally {
                synchronized(lock) { refilling -= dc }
            }
        }
    }

    fun close() {
        maintenance?.cancel()
        val all = synchronized(lock) { idle.values.flatMap { it.toList() }.also { idle.clear() } }
        all.forEach { runCatching { it.ws.close() } }
    }

    private companion object {
        const val MAX_AGE_NS = 100_000_000_000L
        const val CHECK_INTERVAL_MS = 5_000L
        const val PER_DC_LIMIT = 1
    }
}
