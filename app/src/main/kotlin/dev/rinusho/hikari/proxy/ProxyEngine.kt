package dev.rinusho.hikari.proxy

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * Local MTProto proxy: accepts Telegram's obfuscated connections on 127.0.0.1 and relays them to
 * Telegram over WebSocket. Fallback order: CF worker, CF proxy (HTTP/2 for media, else WebSocket), TCP.
 * Port of proxy/tg_ws_proxy.py + proxy/bridge.py.
 */
class ProxyEngine(private val cfg: ProxyConfig) {
    private val executor = Executors.newCachedThreadPool { r -> Thread(r, "tgws-io").apply { isDaemon = true } }
    private val scope = CoroutineScope(SupervisorJob() + executor.asCoroutineDispatcher())
    private val secret = Proto.unhex(cfg.secretHex)
    private val balancer = Balancer()
    private val pool = WsPool(cfg, scope)
    private val workerPool = CfWorkerPool(cfg, scope)
    private val h2Pool: CfH2Pool? = if (cfg.h2Enabled) CfH2Pool(scope, balancer) else null
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
        scope.launch {
            // Profile the masking site first so our forged ServerHello looks like its real one.
            FakeTls.setProfiledAppdataLen(null)
            if (cfg.fakeTlsDomain.isNotBlank()) {
                val len = FakeTls.probeAppdataLen(cfg.fakeTlsDomain)
                FakeTls.setProfiledAppdataLen(len)
                if (len == null) ProxyLog.w("Fake TLS profile unavailable, ServerHello uses random record sizes")
                else ProxyLog.i("Fake TLS profile: first encrypted record $len bytes")
            }
            acceptLoop(ss)
        }
        scope.launch { cfDomainLoop() }
        pool.start()
        workerPool.start()

        ProxyLog.i("Listening on ${cfg.host}:${cfg.port}")
        ProxyLog.i("DC targets: ${cfg.dcRedirects.entries.joinToString { "DC${it.key}=${it.value}" }}")
        if (cfg.fakeTlsDomain.isNotBlank()) ProxyLog.i("Fake TLS: ${cfg.fakeTlsDomain}")
        if (cfg.cfFallback) ProxyLog.i("CF proxy fallback enabled")
        if (cfg.cfWorkerDomains.isNotEmpty()) ProxyLog.i("CF worker: ${cfg.cfWorkerDomains.joinToString()}")
        if (h2Pool != null) ProxyLog.i("CF H2 media: enabled")
        if (cfg.disableSecure) ProxyLog.i("No secure: port 80 for CF proxy / worker")
        if (cfg.forceTestDc) ProxyLog.i("All traffic goes to Telegram test DCs")
        if (cfg.proxyProtocol) ProxyLog.i("PROXY protocol v1 header expected")
    }

    fun stop() {
        runCatching { server?.close() }
        pool.close()
        workerPool.close()
        h2Pool?.let { p ->
            Thread({ runBlocking { runCatching { p.close() } } }, "tgws-h2-close").apply { isDaemon = true; start() }
        }
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

    /** The first 64 obfuscated bytes plus the streams MTProto continues on (raw TCP or inside Fake TLS). */
    private class ClientStream(val handshake: ByteArray, val input: InputStream, val output: OutputStream, val label: String)

    private suspend fun handleClient(client: Socket) {
        ProxyStats.total.incrementAndGet()
        ProxyStats.active.incrementAndGet()
        clients += client
        val label0 = client.remoteSocketAddress?.toString()?.trimStart('/') ?: "?"
        try {
            client.tcpNoDelay = true
            client.soTimeout = 10_000
            val stream = readClientInit(client, label0) ?: return
            val label = stream.label
            client.soTimeout = 0

            val init = Handshake.tryHandshake(stream.handshake, secret)
            if (init == null) {
                ProxyStats.bad.incrementAndGet()
                ProxyLog.w("[$label] bad handshake (wrong secret or protocol)")
                drain(client, stream.input)
                return
            }

            var dc = init.dc
            val isTest = cfg.forceTestDc || dc >= 10000
            if (dc >= 10000) {
                ProxyLog.i("[$label] test DC$dc -> DC${dc - 10000}")
                dc -= 10000
            }
            val dcIdx = if (init.isMedia) -dc else dc
            val tag = if (init.isMedia) " media" else ""
            val relayInit = Handshake.generateRelayInit(init.protoTag, dcIdx)
            val ctx = Handshake.buildCrypto(init.prekeyIv, secret, relayInit)
            val newSplitter = { MsgSplitter(init.protoTag) }
            val route = Route(client, stream.input, stream.output, relayInit, label, dc, isTest, init, ctx)

            val ws = pool.get(dc, init.isMedia, isTest)
            if (ws != null) {
                ProxyLog.i("[$label] DC$dc$tag -> WS pool hit")
                ProxyStats.ws.incrementAndGet()
                ws.send(relayInit)
                bridge(route, ws, newSplitter(), "DC$dc${if (init.isMedia) "m" else ""}")
                return
            }

            ProxyLog.i("[$label] DC$dc$tag: WS pool unavailable -> fallback")
            if (!fallback(route, newSplitter)) ProxyLog.w("[$label] DC$dc$tag: no fallback available")
        } catch (e: Exception) {
            ProxyLog.d("[$label0] ended: $e")
        } finally {
            ProxyStats.active.decrementAndGet()
            clients -= client
            runCatching { client.close() }
        }
    }

    private class Route(
        val client: Socket, val input: InputStream, val output: OutputStream, val relayInit: ByteArray,
        val label: String, val dc: Int, val isTest: Boolean, val init: ClientInit, val ctx: CryptoCtx,
    )

    /** Optional PROXY header, then either a raw obfuscated init or a Fake TLS handshake carrying it. */
    private fun readClientInit(client: Socket, label0: String): ClientStream? {
        val rawIn = client.getInputStream()
        val rawOut = client.getOutputStream()
        var label = label0

        if (cfg.proxyProtocol) {
            val line = readLine(rawIn, 107) ?: return null
            val src = parseProxyLine(line)
            if (src == null) ProxyLog.d("[$label] expected PROXY header, got: ${line.take(60)}")
            else if (src.isNotEmpty()) label = src
        }

        val first = rawIn.read()
        if (first < 0) { ProxyLog.d("[$label] client disconnected before handshake"); return null }
        val masking = cfg.fakeTlsDomain.trim()

        if (masking.isEmpty()) {
            return ClientStream(byteArrayOf(first.toByte()) + readFully(rawIn, Proto.HANDSHAKE_LEN - 1), rawIn, rawOut, label)
        }

        if (first != FakeTls.RECORD_HANDSHAKE) {
            ProxyLog.d("[$label] non-TLS byte 0x%02X -> HTTP redirect".format(first))
            rawOut.write(
                ("HTTP/1.1 301 Moved Permanently\r\nLocation: https://$masking/\r\n" +
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").toByteArray(),
            )
            rawOut.flush()
            return null
        }

        val header = byteArrayOf(first.toByte()) + readFully(rawIn, 4)
        val recordLen = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        val hello = header + readFully(rawIn, recordLen)

        val verified = FakeTls.verifyClientHello(hello, secret)
        // A recorded hello stays valid for minutes; answering it again would tell a prober this is a proxy.
        val replayed = verified != null && !FakeTls.replayCache.firstSeen(verified.clientRandom)
        if (verified == null || replayed) {
            ProxyLog.d("[$label] Fake TLS ${if (replayed) "hello replayed" else "verify failed"} (size=${hello.size}) -> masking")
            client.soTimeout = 0
            FakeTls.proxyToMaskingDomain(rawIn, rawOut, hello, masking, label)
            return null
        }
        ProxyLog.d("[$label] Fake TLS handshake ok (ts=${verified.timestamp})")

        val serverHello = FakeTls.buildServerHello(secret, verified.clientRandom, verified.sessionId, FakeTls.parseClientHello(hello))
        Thread.sleep(FakeTls.SERVER_HELLO_DELAY_MS.random())
        rawOut.write(serverHello)
        rawOut.flush()

        val tin = FakeTls.Input(rawIn)
        val tout = FakeTls.Output(rawOut)
        return ClientStream(readFully(tin, Proto.HANDSHAKE_LEN), tin, tout, label)
    }

    private fun readFully(input: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(b, got, n - got)
            if (r < 0) throw EOFException("client disconnected during handshake")
            got += r
        }
        return b
    }

    private fun readLine(input: InputStream, max: Int): String? {
        val sb = StringBuilder()
        while (sb.length < max) {
            val c = input.read()
            if (c < 0) return null
            if (c == '\n'.code) return sb.toString()
            sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun drain(client: Socket, input: InputStream) {
        runCatching {
            client.soTimeout = 10_000
            val buf = ByteArray(4096)
            var left = 64 * 1024
            while (left > 0) {
                val n = input.read(buf, 0, minOf(buf.size, left))
                if (n < 0) break
                left -= n
            }
        }
    }

    // ───────────────────────────── fallbacks

    private suspend fun fallback(r: Route, newSplitter: () -> MsgSplitter): Boolean {
        val dst = (if (r.isTest) Proto.DC_TEST_IPS else Proto.DC_DEFAULT_IPS)[r.dc]
        val useCf = cfg.cfFallback && !r.isTest
        val media = if (r.init.isMedia) " media" else ""

        val methods = buildList {
            if (cfg.cfWorkerDomains.isNotEmpty() && dst != null) add("cf_worker")
            if (useCf) add("cf")
            if (dst != null) add("tcp")
        }
        for (method in methods) {
            val ok = when (method) {
                "cf_worker" -> workerFallback(r, dst!!, media)
                "cf" -> cfFallback(r, newSplitter, media)
                else -> tcpFallback(r, dst!!, media)
            }
            if (ok) return true
        }
        return false
    }

    private fun workerFallback(r: Route, dst: String, media: String): Boolean {
        var picked = if (r.isTest) null else workerPool.get(r.dc, dst)
        if (picked != null) {
            ProxyLog.i("[${r.label}] DC${r.dc}$media -> CF worker pool hit via ${picked.second} for $dst")
        } else {
            ProxyLog.i("[${r.label}] DC${r.dc}$media -> trying CF worker for $dst")
            picked = workerPool.connectNow(r.dc, dst, 10_000)
        }
        val ws = picked?.first ?: return false
        ProxyStats.cf.incrementAndGet()
        ProxyStats.worker.incrementAndGet()
        ws.send(r.relayInit)
        bridge(r, ws, null, "DC${r.dc}")
        return true
    }

    private suspend fun cfFallback(r: Route, newSplitter: () -> MsgSplitter, media: String): Boolean {
        if (r.init.isMedia && h2Pool != null) {
            val channel = h2Pool.open(r.dc, r.label)
            if (channel != null) {
                ProxyStats.h2.incrementAndGet()
                ProxyStats.cf.incrementAndGet()
                bridgeH2(r.input, r.output, channel, r.ctx, r.init.protoTag) { runCatching { r.client.close() } }
                return true
            }
        }
        ProxyLog.i("[${r.label}] DC${r.dc}$media -> trying CF proxy")
        for (base in balancer.domainsFor(r.dc)) {
            val domain = "kws${r.dc}.$base"
            val ws = try {
                RawWebSocket.connect(domain, domain, timeoutMs = 10_000, secure = !cfg.disableSecure)
            } catch (e: Exception) {
                ProxyLog.w("[${r.label}] DC${r.dc}$media CF proxy failed: ${e.javaClass.simpleName}")
                continue
            }
            if (balancer.setActive(r.dc, base)) ProxyLog.i("[${r.label}] switched active CF domain")
            ProxyStats.cf.incrementAndGet()
            ws.send(r.relayInit)
            bridge(r, ws, newSplitter(), "DC${r.dc}")
            return true
        }
        return false
    }

    private fun tcpFallback(r: Route, dst: String, media: String): Boolean {
        val now = System.nanoTime()
        if (now < (tcpRetryAfter[dst] ?: 0L)) {
            ProxyLog.d("[${r.label}] TCP fallback to $dst skipped (back-off)")
            return false
        }
        val sock = Socket()
        try {
            ProxyLog.i("[${r.label}] DC${r.dc}$media -> TCP $dst:443")
            sock.tcpNoDelay = true
            sock.connect(InetSocketAddress(dst, 443), 10_000)
            sock.getOutputStream().apply { write(r.relayInit); flush() }
        } catch (e: Exception) {
            runCatching { sock.close() }
            val f = (tcpFailures[dst] ?: 0) + 1
            tcpFailures[dst] = f
            val delaySec = minOf(30L * (1L shl minOf(f - 1, 7)), 3600L)
            tcpRetryAfter[dst] = System.nanoTime() + delaySec * 1_000_000_000L
            ProxyLog.w("[${r.label}] TCP fallback to $dst failed: ${e.javaClass.simpleName}; retry in ${delaySec}s")
            return false
        }
        tcpFailures.remove(dst)
        tcpRetryAfter.remove(dst)
        ProxyStats.tcp.incrementAndGet()
        bridge(r, TcpUpstream(sock), null, "DC${r.dc}")
        return true
    }

    // ───────────────────────────── bridge

    /**
     * Bidirectional relay with re-encryption:
     * client ciphertext -> decrypt(client key) -> encrypt(telegram key) -> upstream, and back.
     */
    private fun bridge(r: Route, up: Upstream, splitter: MsgSplitter?, tag: String) {
        val ctx = r.ctx
        val start = System.nanoTime()
        var upBytes = 0L
        var downBytes = 0L
        val closeBoth = {
            runCatching { up.close() }
            runCatching { r.client.close() }
        }

        val upThread = Thread({
            try {
                val buf = ByteArray(65536)
                while (true) {
                    val n = r.input.read(buf)
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
            while (true) {
                val data = up.recv() ?: break
                ProxyStats.down.addAndGet(data.size.toLong())
                downBytes += data.size
                val out = ctx.cltEnc.update(ctx.tgDec.update(data))
                r.output.write(out)
                r.output.flush()
            }
        } catch (_: Exception) {
        } finally {
            closeBoth()
        }
        upThread.join(2000)
        ProxyLog.i(
            "[${r.label}] $tag closed: ↑${Proto.humanBytes(upBytes)} ↓${Proto.humanBytes(downBytes)} " +
                "in ${"%.1f".format((System.nanoTime() - start) / 1e9)}s",
        )
    }
}
