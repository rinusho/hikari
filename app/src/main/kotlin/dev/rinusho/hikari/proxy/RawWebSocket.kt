package dev.rinusho.hikari.proxy

import android.util.Base64
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class WsHandshakeError(val status: Int, val statusLine: String, val location: String?) :
    IOException("HTTP $status: $statusLine") {
    val isRedirect get() = status in listOf(301, 302, 303, 307, 308)
}

/** Minimal blocking RFC 6455 client (binary frames only), port of proxy/raw_websocket.py. */
class RawWebSocket private constructor(
    private val sock: Socket,
    private val input: InputStream,
    private val output: OutputStream,
) : Upstream {
    @Volatile
    var closed = false
        private set
    val createdAt = System.nanoTime()
    private val writeLock = Any()
    private var frag = java.io.ByteArrayOutputStream()

    val isDead get() = closed || sock.isClosed || sock.isInputShutdown || sock.isOutputShutdown

    override fun send(parts: List<ByteArray>) {
        if (closed) throw IOException("WebSocket closed")
        synchronized(writeLock) {
            for (p in parts) output.write(buildFrame(OP_BINARY, p))
            output.flush()
        }
    }

    fun send(data: ByteArray) = send(listOf(data))

    override fun recv(): ByteArray? {
        while (!closed) {
            val hdr = readN(2)
            val fin = hdr[0].toInt() and 0x80 != 0
            val opcode = hdr[0].toInt() and 0x0F
            var len = (hdr[1].toInt() and 0x7F).toLong()
            if (len == 126L) {
                val b = readN(2)
                len = (((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)).toLong()
            } else if (len == 127L) {
                val b = readN(8)
                len = 0
                for (x in b) len = (len shl 8) or (x.toLong() and 0xFF)
            }
            if (len > MAX_MESSAGE) throw IOException("WS frame too large: $len")
            val masked = hdr[1].toInt() and 0x80 != 0
            val mask = if (masked) readN(4) else null
            val payload = readN(len.toInt())
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()

            when (opcode) {
                OP_CLOSE -> {
                    closed = true
                    runCatching {
                        synchronized(writeLock) {
                            output.write(buildFrame(OP_CLOSE, payload.copyOf(minOf(2, payload.size))))
                            output.flush()
                        }
                    }
                    return null
                }
                OP_PING -> runCatching {
                    synchronized(writeLock) {
                        output.write(buildFrame(OP_PONG, payload))
                        output.flush()
                    }
                }
                OP_PONG -> Unit
                OP_CONT, OP_TEXT, OP_BINARY -> {
                    if (fin && frag.size() == 0) return payload
                    frag.write(payload)
                    if (frag.size() > MAX_MESSAGE) throw IOException("WS message too large")
                    if (fin) {
                        val msg = frag.toByteArray()
                        frag = java.io.ByteArrayOutputStream()
                        return msg
                    }
                }
            }
        }
        return null
    }

    override fun close() {
        if (!closed) {
            closed = true
            runCatching {
                synchronized(writeLock) {
                    output.write(buildFrame(OP_CLOSE, ByteArray(0)))
                    output.flush()
                }
            }
        }
        runCatching { sock.close() }
    }

    private fun readN(n: Int): ByteArray {
        val buf = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = input.read(buf, got, n - got)
            if (r < 0) throw EOFException("ws eof")
            got += r
        }
        return buf
    }

    private fun buildFrame(opcode: Int, data: ByteArray): ByteArray {
        val len = data.size
        val hdrLen = 2 + (if (len < 126) 0 else if (len < 65536) 2 else 8) + 4
        val out = ByteArray(hdrLen + len)
        out[0] = (0x80 or opcode).toByte()
        var p = 1
        when {
            len < 126 -> out[p++] = (0x80 or len).toByte()
            len < 65536 -> {
                out[p++] = (0x80 or 126).toByte()
                out[p++] = (len shr 8).toByte()
                out[p++] = len.toByte()
            }
            else -> {
                out[p++] = (0x80 or 127).toByte()
                for (i in 7 downTo 0) out[p++] = ((len.toLong() shr (8 * i)) and 0xFF).toByte()
            }
        }
        val mask = Proto.randomBytes(4)
        System.arraycopy(mask, 0, out, p, 4)
        p += 4
        for (i in 0 until len) out[p + i] = (data[i].toInt() xor mask[i and 3].toInt()).toByte()
        return out
    }

    companion object {
        const val OP_CONT = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA
        private const val MAX_MESSAGE = 16 * 1024 * 1024

        /**
         * @param host   address to dial (IP or hostname)
         * @param domain value for the Host header (and SNI unless [sni] is given)
         * @param sni    domain fronting: send this SNI while the Host header stays [domain]
         */
        fun connect(
            host: String,
            domain: String,
            timeoutMs: Int = 10_000,
            path: String = Proto.WS_PATH,
            sni: String? = null,
            secure: Boolean = true,
        ): RawWebSocket {
            val plain = Socket()
            var sock: Socket = plain
            try {
                plain.tcpNoDelay = true
                plain.connect(InetSocketAddress(host, if (secure) 443 else 80), timeoutMs)
                plain.soTimeout = timeoutMs
                if (secure) {
                    val name = sni ?: domain
                    val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                        .createSocket(plain, name, 443, true) as SSLSocket
                    ssl.sslParameters = ssl.sslParameters.also { it.serverNames = listOf(SNIHostName(name)) }
                    sock = ssl
                    ssl.startHandshake()
                    // With fronting the certificate is for the real host, so only the chain is verified.
                    if (sni == null && !HttpsURLConnection.getDefaultHostnameVerifier().verify(domain, ssl.session)) {
                        throw SSLPeerUnverifiedException("hostname mismatch for $domain")
                    }
                }
                val input = sock.getInputStream().buffered(64 * 1024)
                val output = sock.getOutputStream()

                val key = Base64.encodeToString(Proto.randomBytes(16), Base64.NO_WRAP)
                val req = "GET $path HTTP/1.1\r\nHost: $domain\r\nUpgrade: websocket\r\n" +
                    "Connection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n\r\n"
                output.write(req.toByteArray(Charsets.US_ASCII))
                output.flush()

                val lines = ArrayList<String>()
                while (true) {
                    val line = readLine(input)
                    if (line.isEmpty()) break
                    lines += line
                }
                if (lines.isEmpty()) throw WsHandshakeError(0, "empty response", null)
                val status = lines[0].split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (status != 101) {
                    val loc = lines.drop(1).firstOrNull { it.startsWith("location:", ignoreCase = true) }
                        ?.substringAfter(':')?.trim()
                    throw WsHandshakeError(status, lines[0], loc)
                }
                sock.soTimeout = 0
                return RawWebSocket(sock, input, output)
            } catch (t: Throwable) {
                runCatching { sock.close() }
                runCatching { plain.close() }
                throw t
            }
        }

        private fun readLine(input: InputStream): String {
            val sb = StringBuilder()
            while (true) {
                val c = input.read()
                if (c < 0) throw EOFException("eof in handshake")
                if (c == '\n'.code) break
                if (c != '\r'.code) sb.append(c.toChar())
                if (sb.length > 8192) throw IOException("header too long")
            }
            return sb.toString()
        }
    }
}

/** A bidirectional pipe to Telegram: either a WebSocket or a raw TCP connection. */
interface Upstream {
    fun send(parts: List<ByteArray>)
    fun recv(): ByteArray?
    fun close()
}

class TcpUpstream(private val sock: Socket) : Upstream {
    private val out = sock.getOutputStream()
    private val inp = sock.getInputStream()
    private val buf = ByteArray(65536)

    override fun send(parts: List<ByteArray>) {
        for (p in parts) out.write(p)
        out.flush()
    }

    override fun recv(): ByteArray? {
        val n = inp.read(buf)
        return if (n < 0) null else buf.copyOf(n)
    }

    override fun close() {
        runCatching { sock.close() }
    }
}
