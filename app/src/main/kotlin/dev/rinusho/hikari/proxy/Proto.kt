package dev.rinusho.hikari.proxy

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** MTProto obfuscated-transport constants and helpers (port of proxy/utils.py + tg_ws_proxy.py). */
object Proto {
    const val HANDSHAKE_LEN = 64
    const val SKIP_LEN = 8
    const val PREKEY_LEN = 32
    const val KEY_LEN = 32
    const val IV_LEN = 16
    const val TAG_POS = 56
    const val DC_POS = 60

    const val ABRIDGED = 0xEFEFEFEF.toInt()
    const val INTERMEDIATE = 0xEEEEEEEE.toInt()
    const val PADDED = 0xDDDDDDDD.toInt()

    private val RESERVED_STARTS = setOf(
        0x48454144, // HEAD
        0x504F5354, // POST
        0x47455420, // GET
        0xEEEEEEEE.toInt(),
        0xDDDDDDDD.toInt(),
        0x16030102,
        0x4F505449, // OPTI
    )

    /** Datacenter IPs used by the plain-TCP fallback. */
    val DC_DEFAULT_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    /** Telegram test datacenters (plain-TCP fallback for test DCs). */
    val DC_TEST_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.10",
        2 to "149.154.167.40",
        3 to "149.154.175.117",
    )

    const val WS_PATH = "/apiws"
    const val WS_PATH_TEST = "/apiws_test"

    fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
        val d = if (dc == 203) 2 else dc
        return if (!isMedia) listOf("kws$d.web.telegram.org")
        else listOf("kws$d-1.web.telegram.org", "kws$d.web.telegram.org")
    }

    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun intAt(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    fun tagBytes(tag: Int): ByteArray = byteArrayOf(
        (tag ushr 24).toByte(), (tag ushr 16).toByte(), (tag ushr 8).toByte(), tag.toByte(),
    )

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun humanBytes(n: Long): String {
        var v = n.toDouble()
        for (u in arrayOf("B", "KB", "MB", "GB")) {
            if (v < 1024) return if (u == "B") "${v.toLong()} $u" else "%.1f %s".format(v, u)
            v /= 1024
        }
        return "%.1f TB".format(v)
    }
}

/** Streaming AES-256-CTR keystream (encrypt == decrypt). Not thread-safe; one per direction. */
class Ctr(key: ByteArray, iv: ByteArray) {
    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").also {
        it.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }

    fun update(d: ByteArray, off: Int = 0, len: Int = d.size - off): ByteArray =
        cipher.update(d, off, len) ?: ByteArray(0)

    fun skip(n: Int) {
        cipher.update(ByteArray(n))
    }
}

class CryptoCtx(
    val cltDec: Ctr, // decrypt data from client
    val cltEnc: Ctr, // encrypt data to client
    val tgEnc: Ctr, // encrypt data to telegram
    val tgDec: Ctr, // decrypt data from telegram
)

class ClientInit(val dc: Int, val isMedia: Boolean, val protoTag: Int, val prekeyIv: ByteArray)

object Handshake {
    /** Validates the client's 64-byte obfuscated init against the secret. */
    fun tryHandshake(hs: ByteArray, secret: ByteArray): ClientInit? {
        val prekeyIv = hs.copyOfRange(Proto.SKIP_LEN, Proto.SKIP_LEN + Proto.PREKEY_LEN + Proto.IV_LEN)
        val key = Proto.sha256(prekeyIv.copyOfRange(0, Proto.PREKEY_LEN), secret)
        val dec = Ctr(key, prekeyIv.copyOfRange(Proto.PREKEY_LEN, prekeyIv.size))
        val d = dec.update(hs)

        val tag = Proto.intAt(d, Proto.TAG_POS)
        if (tag != Proto.ABRIDGED && tag != Proto.INTERMEDIATE && tag != Proto.PADDED) return null

        val raw = (d[Proto.DC_POS].toInt() and 0xFF) or ((d[Proto.DC_POS + 1].toInt() and 0xFF) shl 8)
        val dcIdx = raw.toShort().toInt()
        return ClientInit(kotlin.math.abs(dcIdx), dcIdx < 0, tag, prekeyIv)
    }

    /** Builds the 64-byte obfuscated init that is sent to Telegram. */
    fun generateRelayInit(protoTag: Int, dcIdx: Int): ByteArray {
        var rnd: ByteArray
        while (true) {
            rnd = Proto.randomBytes(Proto.HANDSHAKE_LEN)
            if ((rnd[0].toInt() and 0xFF) == 0xEF) continue
            if (Proto.intAt(rnd, 0) in RESERVED) continue
            if (Proto.intAt(rnd, 4) == 0) continue
            break
        }
        val encKey = rnd.copyOfRange(Proto.SKIP_LEN, Proto.SKIP_LEN + Proto.PREKEY_LEN)
        val encIv = rnd.copyOfRange(Proto.SKIP_LEN + Proto.PREKEY_LEN, Proto.SKIP_LEN + Proto.PREKEY_LEN + Proto.IV_LEN)
        val full = Ctr(encKey, encIv).update(rnd)

        val tail = ByteArray(8)
        val tag = Proto.tagBytes(protoTag)
        System.arraycopy(tag, 0, tail, 0, 4)
        tail[4] = dcIdx.toByte()
        tail[5] = (dcIdx shr 8).toByte()
        val pad = Proto.randomBytes(2)
        tail[6] = pad[0]
        tail[7] = pad[1]

        val out = rnd.copyOf()
        for (i in 0 until 8) {
            val keystream = (full[56 + i].toInt() xor rnd[56 + i].toInt())
            out[56 + i] = (tail[i].toInt() xor keystream).toByte()
        }
        return out
    }

    private val RESERVED = setOf(
        0x48454144, 0x504F5354, 0x47455420, 0xEEEEEEEE.toInt(), 0xDDDDDDDD.toInt(), 0x16030102, 0x4F505449,
    )

    fun buildCrypto(clientPrekeyIv: ByteArray, secret: ByteArray, relayInit: ByteArray): CryptoCtx {
        val pk = Proto.PREKEY_LEN
        // client -> proxy ("dec"), key = SHA256(prekey + secret)
        val cltDecKey = Proto.sha256(clientPrekeyIv.copyOfRange(0, pk), secret)
        val cltDecIv = clientPrekeyIv.copyOfRange(pk, clientPrekeyIv.size)
        // proxy -> client ("enc"): reversed prekey+iv
        val rev = clientPrekeyIv.reversedArray()
        val cltEncKey = Proto.sha256(rev.copyOfRange(0, pk), secret)
        val cltEncIv = rev.copyOfRange(pk, rev.size)

        val cltDec = Ctr(cltDecKey, cltDecIv)
        val cltEnc = Ctr(cltEncKey, cltEncIv)
        cltDec.skip(Proto.HANDSHAKE_LEN) // past the 64-byte init

        // relay side: plain obfuscation without secret hashing
        val relayKey = relayInit.copyOfRange(Proto.SKIP_LEN, Proto.SKIP_LEN + pk)
        val relayIv = relayInit.copyOfRange(Proto.SKIP_LEN + pk, Proto.SKIP_LEN + pk + Proto.IV_LEN)
        val relayRev = relayInit.copyOfRange(Proto.SKIP_LEN, Proto.SKIP_LEN + pk + Proto.IV_LEN).reversedArray()

        val tgEnc = Ctr(relayKey, relayIv)
        val tgDec = Ctr(relayRev.copyOfRange(0, Proto.KEY_LEN), relayRev.copyOfRange(Proto.KEY_LEN, relayRev.size))
        tgEnc.skip(Proto.HANDSHAKE_LEN)
        return CryptoCtx(cltDec, cltEnc, tgEnc, tgDec)
    }
}

/**
 * Splits the TCP byte stream into individual MTProto transport packets so that each one is sent
 * as a separate WebSocket frame (Telegram's WS endpoint expects frame == packet).
 */
class MsgSplitter(private val proto: Int) {
    private var cipher = ByteArray(0)
    private var plain = ByteArray(0)
    private var disabled = false

    fun split(chunk: ByteArray, plainChunk: ByteArray): List<ByteArray> {
        if (chunk.isEmpty()) return emptyList()
        if (disabled) return listOf(chunk)

        cipher += chunk
        plain += plainChunk

        val parts = ArrayList<ByteArray>()
        var off = 0
        val len = cipher.size
        while (off < len) {
            val pl = nextLen(off, len - off) ?: break
            if (pl <= 0) {
                parts += cipher.copyOfRange(off, len)
                off = len
                disabled = true
                break
            }
            parts += cipher.copyOfRange(off, off + pl)
            off += pl
        }
        if (off > 0) {
            cipher = cipher.copyOfRange(off, cipher.size)
            plain = plain.copyOfRange(off, plain.size)
        }
        return parts
    }

    fun flush(): List<ByteArray> {
        if (cipher.isEmpty()) return emptyList()
        val tail = cipher
        cipher = ByteArray(0)
        plain = ByteArray(0)
        return listOf(tail)
    }

    private fun nextLen(off: Int, avail: Int): Int? {
        if (avail <= 0) return null
        return when (proto) {
            Proto.ABRIDGED -> abridged(off, avail)
            Proto.INTERMEDIATE, Proto.PADDED -> intermediate(off, avail)
            else -> 0
        }
    }

    private fun abridged(off: Int, avail: Int): Int? {
        val first = plain[off].toInt() and 0xFF
        val payload: Int
        val header: Int
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) return null
            payload = ((plain[off + 1].toInt() and 0xFF) or
                ((plain[off + 2].toInt() and 0xFF) shl 8) or
                ((plain[off + 3].toInt() and 0xFF) shl 16)) * 4
            header = 4
        } else {
            payload = (first and 0x7F) * 4
            header = 1
        }
        if (payload <= 0) return 0
        val packet = header + payload
        return if (avail < packet) null else packet
    }

    private fun intermediate(off: Int, avail: Int): Int? {
        if (avail < 4) return null
        val v = (plain[off].toInt() and 0xFF) or
            ((plain[off + 1].toInt() and 0xFF) shl 8) or
            ((plain[off + 2].toInt() and 0xFF) shl 16) or
            ((plain[off + 3].toInt() and 0xFF) shl 24)
        val payload = v and 0x7FFFFFFF
        if (payload <= 0) return 0
        val packet = 4 + payload
        return if (avail < packet) null else packet
    }
}
