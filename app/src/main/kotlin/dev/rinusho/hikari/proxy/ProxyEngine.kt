package dev.rinusho.hikari.proxy

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch

/**
 * Local MTProto proxy: accepts Telegram's obfuscated connections on 127.0.0.1 and relays them to
 * Telegram over WebSocket (fallbacks: Cloudflare proxy domains, then plain TCP).
 * Port of proxy/tg_ws_proxy.py + proxy/bridge.py (without Fake TLS / CF worker / HTTP2 media).
 */
class ProxyEngine(private val cfg: ProxyConfig) {
    private val executor = Executors.newCachedThreadPool { r -> Thread(r, "tgws-io").apply { isDaemon = true } }
    private val scope = CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher())
    private val secret = Proto.unhex(cfg.secretHex)
    private val balancer = Balancer()
    private val pool = WsPool(cfg, scope)
    private val clients = ConcurrentHashMap.newKeySet<Socket>()
    private var server: ServerSocket? = null

    // plain-TCP fallback back-off, per destination
    private val tcpFailures = ConcurrentHashMap<String, Int>()
    private val tcpRetryAfter = ConcurrentHashMap<String, Long>()

    /** Binds the listening socket (throws [IOException] if the port is taken) and starts serving. */
    fun start() {
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName(cfg.host), cfg.port), 128)
        server = ss

        ProxyStats.reset()
        scope.launch { acceptLoop(ss) }
        scope.launch { cfDomainLoop() }
        pool.start()

        ProxyLog.i("Listening on ${cfg.host}:${cfg.port}")
        ProxyLog.i("DC targets: ${cfg.dcRedirects.entries.joinToString { "DC${it.key}=${it.value}" }}")
        if (cfg.cfFallback) ProxyLog.i("CF proxy fallback enabled")
    }

    fun stop() {
        runCatching { server?.close() }
        pool.close()
        clients.forEach { runCatching { it.close() } }
        clients.clear()
        scope.cancel()
        executor.shutdownNow()
        ProxyLog.i("Stopped")
    }

    private suspend fun acceptLoop(ss: ServerSocket) {
        while (scope.isActive && !ss.isClosed) {
            val s = try {
                ss.accept()
            } catch (e: IOException) {
                if (!ss.isClosed) ProxyLog.w("accept failed: $e")
                break
            }
            scope.launch { handleClient(s) }
        }
    }

    private suspend fun cfDomainLoop() {
        if (!cfg.cfFallback) return
        if (cfg.cfUserDomains.isNotEmpty()) {
            balancer.update(cfg.cfUserDomains)
            return
        }
        balancer.update(CfDomains.defaults)
        while (scope.isActive) {
            val fetched = CfDomains.fetch()
            if (fetched != null) {
                balancer.update(fetched)
                ProxyLog.i("CF domain pool updated (${fetched.size})")
            } else {
                ProxyLog.d("CF domain list refresh failed; keeping current pool")
            }
            delay(3_600_000)
        }
    }

    // ───────────────────────────── per-client

    private fun handleClient(client: Socket) {
        ProxyStats.total.incrementAndGet()
        ProxyStats.active.incrementAndGet()
        clients += client
        val label = client.remoteSocketAddress?.toString()?.trimStart('/') ?: "?"
        try {
            client.tcpNoDelay = true
            client.soTimeout = 10_000
            val input = client.getInputStream()
            val hs = ByteArray(Proto.HANDSHAKE_LEN)
            var got = 0
            while (got < hs.size) {
                val r = input.read(hs, got, hs.size - got)
                if (r < 0) return
                got += r
            }
            client.soTimeout = 0

            val init = Handshake.tryHandshake(hs, secret)
            if (init == null) {
                ProxyStats.bad.incrementAndGet()
                ProxyLog.w("[$label] bad handshake (wrong secret or protocol)")
                drain(client)
                return
            }

            val dcIdx = if (init.isMedia) -init.dc else init.dc
            val tag = if (init.isMedia) " media" else ""
            val relayInit = Handshake.generateRelayInit(init.protoTag, dcIdx)
            val ctx = Handshake.buildCrypto(init.prekeyIv, secret, relayInit)
            val newSplitter = { MsgSplitter(init.protoTag) }

            val ws = pool.get(init.dc, init.isMedia)
            if (ws != null) {
                ProxyLog.i("[$label] DC${init.dc}$tag -> WS")
                ProxyStats.ws.incrementAndGet()
                ws.send(relayInit)
                bridge(client, ws, ctx, newSplitter(), label, "DC${init.dc}${if (init.isMedia) "m" else ""}")
                return
            }

            ProxyLog.i("[$label] DC${init.dc}$tag: no pooled WS -> fallback")
            if (!fallback(client, relayInit, label, init, ctx, newSplitter)) {
                ProxyLog.w("[$label] DC${init.dc}$tag: no fallback available")
            }
        } catch (e: Exception) {
            ProxyLog.d("[$label] ended: $e")
        } finally {
            ProxyStats.active.decrementAndGet()
            clients -= client
            runCatching { client.close() }
        }
    }

    private fun drain(client: Socket) {
        runCatching {
            client.soTimeout = 10_000
            val buf = ByteArray(4096)
            var left = 64 * 1024
            val inp = client.getInputStream()
            while (left > 0) {
                val n = inp.read(buf, 0, minOf(buf.size, left))
                if (n < 0) break
                left -= n
            }
        }
    }

    // ───────────────────────────── fallbacks

    private fun fallback(
        client: Socket, relayInit: ByteArray, label: String, init: ClientInit,
        ctx: CryptoCtx, newSplitter: () -> MsgSplitter,
    ): Boolean {
        val dst = Proto.DC_DEFAULT_IPS[init.dc]
        val media = if (init.isMedia) " media" else ""

        if (cfg.cfFallback) {
            for (base in balancer.domainsFor(init.dc)) {
                val domain = "kws${init.dc}.$base"
                val ws = try {
                    RawWebSocket.connect(domain, domain, timeoutMs = 10_000)
                } catch (e: Exception) {
                    ProxyLog.w("[$label] DC${init.dc}$media CF proxy failed: ${e.javaClass.simpleName}")
                    continue
                }
                if (balancer.setActive(init.dc, base)) ProxyLog.i("[$label] switched active CF domain")
                ProxyLog.i("[$label] DC${init.dc}$media -> CF proxy")
                ProxyStats.cf.incrementAndGet()
                ws.send(relayInit)
                bridge(client, ws, ctx, newSplitter(), label, "DC${init.dc}")
                return true
            }
        }

        if (dst != null) {
            val now = System.nanoTime()
            if (now < (tcpRetryAfter[dst] ?: 0L)) {
                ProxyLog.d("[$label] TCP fallback to $dst skipped (back-off)")
                return false
            }
            val sock = Socket()
            try {
                ProxyLog.i("[$label] DC${init.dc}$media -> TCP $dst:443")
                sock.tcpNoDelay = true
                sock.connect(InetSocketAddress(dst, 443), 10_000)
                sock.getOutputStream().apply { write(relayInit); flush() }
            } catch (e: Exception) {
                runCatching { sock.close() }
                val f = (tcpFailures[dst] ?: 0) + 1
                tcpFailures[dst] = f
                val delaySec = minOf(30L * (1L shl minOf(f - 1, 7)), 3600L)
                tcpRetryAfter[dst] = System.nanoTime() + delaySec * 1_000_000_000L
                ProxyLog.w("[$label] TCP fallback to $dst failed: ${e.javaClass.simpleName}; retry in ${delaySec}s")
                return false
            }
            tcpFailures.remove(dst)
            tcpRetryAfter.remove(dst)
            ProxyStats.tcp.incrementAndGet()
            bridge(client, TcpUpstream(sock), ctx, null, label, "DC${init.dc}")
            return true
        }
        return false
    }

    // ───────────────────────────── bridge

    /**
     * Bidirectional relay with re-encryption:
     * client ciphertext -> decrypt(client key) -> encrypt(telegram key) -> upstream, and back.
     */
    private fun bridge(
        client: Socket, up: Upstream, ctx: CryptoCtx, splitter: MsgSplitter?,
        label: String, tag: String,
    ) {
        val start = System.nanoTime()
        var upBytes = 0L
        var downBytes = 0L
        val closeBoth = {
            runCatching { up.close() }
            runCatching { client.close() }
        }

        val upThread = Thread({
            try {
                val cin = client.getInputStream()
                val buf = ByteArray(65536)
                while (true) {
                    val n = cin.read(buf)
                    if (n < 0) {
                        splitter?.flush()?.takeIf { it.isNotEmpty() }?.let { up.send(it) }
                        break
                    }
                    ProxyStats.up.addAndGet(n.toLong())
                    upBytes += n
                    val plain = ctx.cltDec.update(buf, 0, n)
                    val enc = ctx.tgEnc.update(plain)
                    val parts = splitter?.split(enc, plain) ?: listOf(enc)
                    if (parts.isNotEmpty()) up.send(parts)
                }
            } catch (_: Exception) {
            } finally {
                closeBoth()
            }
        }, "tgws-up").apply { isDaemon = true; start() }

        try {
            val cout = client.getOutputStream()
            while (true) {
                val data = up.recv() ?: break
                ProxyStats.down.addAndGet(data.size.toLong())
                downBytes += data.size
                val out = ctx.cltEnc.update(ctx.tgDec.update(data))
                cout.write(out)
                cout.flush()
            }
        } catch (_: Exception) {
        } finally {
            closeBoth()
        }
        upThread.join(2000)
        ProxyLog.i(
            "[$label] $tag closed: ↑${Proto.humanBytes(upBytes)} ↓${Proto.humanBytes(downBytes)} " +
                "in ${"%.1f".format((System.nanoTime() - start) / 1e9)}s",
        )
    }
}
