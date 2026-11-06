package dev.rinusho.hikari.proxy

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.LinkedHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext

/**
 * Fake TLS (`ee` secret) transport, port of proxy/fake_tls.py.
 *
 * The client opens with a TLS ClientHello whose random carries an HMAC of the secret. Valid hellos
 * get a forged ServerHello + CCS + one ApplicationData record, after which MTProto bytes travel
 * inside ApplicationData records. Anything else is relayed to a real "masking" site.
 */
object FakeTls {
    const val RECORD_HANDSHAKE = 0x16
    const val RECORD_CCS = 0x14
    const val RECORD_APPDATA = 0x17

    private const val CLIENT_RANDOM_OFFSET = 11
    private const val CLIENT_RANDOM_LEN = 32
    private const val SESSION_ID_OFFSET = 44
    private const val SESSION_ID_LEN = 32
    private const val TIMESTAMP_TOLERANCE = 120
    const val APPDATA_MAX = 16384

    private const val EXT_SUPPORTED_VERSIONS = 0x002b
    private const val EXT_KEY_SHARE = 0x0033
    private const val GROUP_X25519 = 0x001d
    private const val GROUP_X25519MLKEM768 = 0x11ec
    private const val X25519_KEY_LEN = 32
    private const val X25519MLKEM768_CLIENT_SHARE_LEN = 1216
    private const val MLKEM768_CIPHERTEXT_LEN = 1088

    private val CIPHER_PREFERENCE = intArrayOf(0x1301, 0x1303, 0x1302)
    private const val APPDATA_MIN = 64
    private val FALLBACK_APPDATA_RANGE = 64..160
    val SERVER_HELLO_DELAY_MS = 8L..24L
    private const val PROFILE_PROBE_TIMEOUT_MS = 5000
    private val CCS_FRAME = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
    private const val SH_RANDOM_OFF = 11

    @Volatile private var profiledAppdataLen: Int? = null

    fun setProfiledAppdataLen(len: Int?) {
        profiledAppdataLen = len?.coerceIn(APPDATA_MIN, APPDATA_MAX)
    }

    // ── replay cache: a repeated, already-accepted ClientHello is an active-probe replay

    private const val REPLAY_WINDOW_MS = (2L * TIMESTAMP_TOLERANCE + 1) * 1000
    private const val REPLAY_CACHE_SIZE = 65536

    class ReplayCache(private val windowMs: Long = REPLAY_WINDOW_MS, private val size: Int = REPLAY_CACHE_SIZE) {
        private val expiry = LinkedHashMap<String, Long>()

        @Synchronized
        fun firstSeen(clientRandom: ByteArray, nowMs: Long = System.nanoTime() / 1_000_000): Boolean {
            val it = expiry.entries.iterator()
            while (it.hasNext() && it.next().value <= nowMs) it.remove()
            val key = Proto.hex(clientRandom)
            if (expiry.containsKey(key)) return false
            if (expiry.size >= size) expiry.remove(expiry.keys.first())
            expiry[key] = nowMs + windowMs
            return true
        }
    }

    val replayCache = ReplayCache()

    class Verified(val clientRandom: ByteArray, val sessionId: ByteArray, val timestamp: Long)

    class HelloInfo(val cipherSuites: Set<Int>, val keyShares: Map<Int, Int>)

    private val EMPTY_INFO = HelloInfo(emptySet(), emptyMap())

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    fun verifyClientHello(data: ByteArray, secret: ByteArray, nowSec: Long = System.currentTimeMillis() / 1000): Verified? {
        val n = data.size
        if (n < 43) return null
        if ((data[0].toInt() and 0xFF) != RECORD_HANDSHAKE) return null
        if (data[5].toInt() != 0x01) return null

        val clientRandom = data.copyOfRange(CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN)
        val zeroed = data.copyOf()
        java.util.Arrays.fill(zeroed, CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN, 0)
        val expected = hmac(secret, zeroed)

        // constant-time comparison of the first 28 bytes
        var diff = 0
        for (i in 0 until 28) diff = diff or (expected[i].toInt() xor clientRandom[i].toInt())
        if (diff != 0) return null

        var ts = 0L
        for (i in 0 until 4) {
            val b = (clientRandom[28 + i].toInt() xor expected[28 + i].toInt()) and 0xFF
            ts = ts or (b.toLong() shl (8 * i))
        }
        if (kotlin.math.abs(nowSec - ts) > TIMESTAMP_TOLERANCE) return null

        var sessionId = ByteArray(SESSION_ID_LEN)
        if (n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43].toInt() == 0x20) {
            sessionId = data.copyOfRange(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN)
        }
        return Verified(clientRandom, sessionId, ts)
    }

    private fun u16(b: ByteArray, off: Int) = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    /** Offered cipher suites and key_share groups; empty info on malformed input. */
    fun parseClientHello(data: ByteArray): HelloInfo {
        try {
            var pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN
            pos += 1 + (data[pos].toInt() and 0xFF)

            val suitesLen = u16(data, pos)
            pos += 2
            val suitesEnd = pos + suitesLen
            if (suitesEnd > data.size) return EMPTY_INFO
            val suites = HashSet<Int>()
            var off = pos
            while (off < suitesEnd - 1) { suites += u16(data, off); off += 2 }
            pos = suitesEnd

            pos += 1 + (data[pos].toInt() and 0xFF)

            val extTotal = u16(data, pos)
            pos += 2
            val extEnd = minOf(pos + extTotal, data.size)
            val keyShares = HashMap<Int, Int>()
            while (pos + 4 <= extEnd) {
                val type = u16(data, pos)
                val len = u16(data, pos + 2)
                pos += 4
                if (type == EXT_KEY_SHARE && pos + 2 <= extEnd) {
                    val sharesEnd = minOf(pos + 2 + u16(data, pos), extEnd)
                    var o = pos + 2
                    while (o + 4 <= sharesEnd) {
                        val group = u16(data, o)
                        val keyLen = u16(data, o + 2)
                        o += 4 + keyLen
                        if (o <= sharesEnd) keyShares.putIfAbsent(group, keyLen)
                    }
                }
                pos += len
            }
            return HelloInfo(suites, keyShares)
        } catch (_: IndexOutOfBoundsException) {
            return EMPTY_INFO
        }
    }

    private fun selectCipherSuite(info: HelloInfo): Int =
        CIPHER_PREFERENCE.firstOrNull { it in info.cipherSuites } ?: CIPHER_PREFERENCE[0]

    /** The client never derives keys from this, so a random field element is enough. */
    private fun x25519PublicKey(): ByteArray {
        val k = Proto.randomBytes(X25519_KEY_LEN)
        k[X25519_KEY_LEN - 1] = (k[X25519_KEY_LEN - 1].toInt() and 0x7f).toByte()
        return k
    }

    private fun serverKeyShare(info: HelloInfo): Pair<Int, ByteArray> =
        if (info.keyShares[GROUP_X25519MLKEM768] == X25519MLKEM768_CLIENT_SHARE_LEN) {
            GROUP_X25519MLKEM768 to (Proto.randomBytes(MLKEM768_CIPHERTEXT_LEN) + x25519PublicKey())
        } else GROUP_X25519 to x25519PublicKey()

    private fun appdataLen(): Int = profiledAppdataLen ?: FALLBACK_APPDATA_RANGE.random()

    private fun be16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    /** ServerHello + CCS + one ApplicationData record, HMAC'd over all three as Telegram clients expect. */
    fun buildServerHello(
        secret: ByteArray, clientRandom: ByteArray, sessionId: ByteArray, info: HelloInfo = EMPTY_INFO,
    ): ByteArray {
        val (group, keyExchange) = serverKeyShare(info)
        val extensions = be16(EXT_SUPPORTED_VERSIONS) + be16(2) + be16(0x0304) +
            be16(EXT_KEY_SHARE) + be16(4 + keyExchange.size) + be16(group) + be16(keyExchange.size) + keyExchange

        val body = byteArrayOf(0x03, 0x03) + ByteArray(32) +
            byteArrayOf(sessionId.size.toByte()) + sessionId +
            be16(selectCipherSuite(info)) + byteArrayOf(0) +
            be16(extensions.size) + extensions
        val message = byteArrayOf(0x02, (body.size shr 16).toByte(), (body.size shr 8).toByte(), body.size.toByte()) + body
        val serverHello = byteArrayOf(RECORD_HANDSHAKE.toByte(), 0x03, 0x03) + be16(message.size) + message

        val len = appdataLen()
        val appRecord = byteArrayOf(RECORD_APPDATA.toByte(), 0x03, 0x03) + be16(len) + Proto.randomBytes(len)

        val response = serverHello + CCS_FRAME + appRecord
        val serverRandom = hmac(secret, clientRandom, response)
        System.arraycopy(serverRandom, 0, response, SH_RANDOM_OFF, 32)
        return response
    }

    // ── profiling the masking site

    /** Size of the first ApplicationData record in a server flight; null = need more, 0 = none possible. */
    fun firstAppdataRecordLen(data: ByteArray, size: Int = data.size): Int? {
        var pos = 0
        while (pos + 5 <= size) {
            val type = data[pos].toInt() and 0xFF
            val recLen = u16(data, pos + 3)
            if (type == RECORD_APPDATA) return recLen
            if (type != RECORD_HANDSHAKE && type != RECORD_CCS) return 0
            pos += 5 + recLen
        }
        return null
    }

    /** A real TLS 1.3 ClientHello for [domain] produced by the platform TLS stack (never completed). */
    private fun buildProbeClientHello(domain: String): ByteArray {
        val ctx = SSLContext.getInstance("TLS").apply { init(null, null, null) }
        val engine = ctx.createSSLEngine(domain, 443)
        engine.useClientMode = true
        engine.sslParameters = engine.sslParameters.also {
            it.serverNames = listOf(SNIHostName(domain))
            it.protocols = arrayOf("TLSv1.3")
            it.applicationProtocols = arrayOf("h2", "http/1.1")
        }
        engine.beginHandshake()
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(ByteBuffer.allocate(0), out)
        out.flip()
        return ByteArray(out.remaining()).also { out.get(it) }
    }

    /** Measures the masking site's first encrypted record so our ServerHello looks alike; null on failure. */
    fun probeAppdataLen(domain: String, port: Int = 443): Int? {
        return try {
            val hello = buildProbeClientHello(domain)
            val deadline = System.nanoTime() + PROFILE_PROBE_TIMEOUT_MS * 1_000_000L
            Socket().use { s ->
                s.connect(InetSocketAddress(domain, port), PROFILE_PROBE_TIMEOUT_MS)
                s.getOutputStream().apply { write(hello); flush() }
                val flight = ByteArray(65536)
                var have = 0
                val input = s.getInputStream()
                while (true) {
                    val left = (deadline - System.nanoTime()) / 1_000_000
                    if (left <= 0) throw IOException("probe timed out")
                    s.soTimeout = left.toInt()
                    val n = input.read(flight, have, flight.size - have)
                    if (n < 0) return null
                    have += n
                    val len = firstAppdataRecordLen(flight, have)
                    if (len != null) return len.takeIf { it > 0 }
                    if (have == flight.size) return null
                }
                @Suppress("UNREACHABLE_CODE") null
            }
        } catch (e: Exception) {
            ProxyLog.w("Fake TLS profile: cannot probe $domain:$port: ${e.javaClass.simpleName}")
            null
        }
    }

    // ── record framing

    fun wrapRecords(data: ByteArray, off: Int = 0, len: Int = data.size - off): ByteArray {
        val out = ByteArrayOutputStream(len + 5 * (len / APPDATA_MAX + 1))
        var o = off
        val end = off + len
        while (o < end) {
            val n = minOf(APPDATA_MAX, end - o)
            out.write(RECORD_APPDATA); out.write(0x03); out.write(0x03)
            out.write(n shr 8); out.write(n)
            out.write(data, o, n)
            o += n
        }
        return out.toByteArray()
    }

    /** MTProto bytes extracted from the ApplicationData records of a Fake TLS connection. */
    class Input(private val raw: InputStream) : InputStream() {
        private var left = 0

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xFF
        }

        override fun read(buf: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            while (left == 0) {
                val hdr = ByteArray(5)
                var got = 0
                while (got < 5) {
                    val r = raw.read(hdr, got, 5 - got)
                    if (r < 0) return -1
                    got += r
                }
                val type = hdr[0].toInt() and 0xFF
                val recLen = u16(hdr, 3)
                if (type == RECORD_CCS) { skipFully(recLen); continue }
                if (type != RECORD_APPDATA) return -1
                left = recLen
            }
            val n = raw.read(buf, off, minOf(len, left))
            if (n < 0) return -1
            left -= n
            return n
        }

        private fun skipFully(n: Int) {
            var rem = n
            val tmp = ByteArray(minOf(n, 512).coerceAtLeast(1))
            while (rem > 0) {
                val r = raw.read(tmp, 0, minOf(rem, tmp.size))
                if (r < 0) throw EOFException()
                rem -= r
            }
        }

        override fun close() = raw.close()
    }

    class Output(private val raw: OutputStream) : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
        override fun write(b: ByteArray, off: Int, len: Int) = raw.write(wrapRecords(b, off, len))
        override fun flush() = raw.flush()
        override fun close() = raw.close()
    }

    /** Relays a connection that failed verification to the real [domain], so probes see an honest site. */
    fun proxyToMaskingDomain(
        clientIn: InputStream, clientOut: OutputStream, initial: ByteArray, domain: String, label: String,
    ) {
        val up = Socket()
        try {
            up.connect(InetSocketAddress(domain, 443), 10_000)
        } catch (e: Exception) {
            runCatching { up.close() }
            ProxyLog.w("[$label] masking: cannot connect to $domain:443: ${e.javaClass.simpleName}")
            return
        }
        ProxyLog.d("[$label] masking -> $domain:443")
        ProxyStats.masked.incrementAndGet()
        try {
            val uout = up.getOutputStream()
            if (initial.isNotEmpty()) { uout.write(initial); uout.flush() }
            val t = Thread({
                runCatching {
                    val buf = ByteArray(16384)
                    val uin = up.getInputStream()
                    while (true) {
                        val n = uin.read(buf)
                        if (n < 0) break
                        clientOut.write(buf, 0, n); clientOut.flush()
                    }
                }
                runCatching { up.close() }
            }, "tgws-mask").apply { isDaemon = true; start() }
            runCatching {
                val buf = ByteArray(16384)
                while (true) {
                    val n = clientIn.read(buf)
                    if (n < 0) break
                    uout.write(buf, 0, n); uout.flush()
                }
            }
            runCatching { up.close() }
            t.join(2000)
        } finally {
            runCatching { up.close() }
        }
    }
}
