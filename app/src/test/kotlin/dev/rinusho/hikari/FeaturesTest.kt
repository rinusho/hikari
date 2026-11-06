package dev.rinusho.hikari

import dev.rinusho.hikari.proxy.Ctr
import dev.rinusho.hikari.proxy.FakeTls
import dev.rinusho.hikari.proxy.H2Framing
import dev.rinusho.hikari.proxy.Proto
import dev.rinusho.hikari.proxy.ProxyConfig
import dev.rinusho.hikari.proxy.parseProxyLine
import dev.rinusho.hikari.proxy.proxyLink
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FeaturesTest {
    private val secret = Proto.randomBytes(16)

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    private fun be16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    /** A ClientHello the way a Telegram client forges it: random = HMAC(secret, hello) with the timestamp xored in. */
    private fun clientHello(secret: ByteArray, ts: Long, withX25519Share: Boolean = true): ByteArray {
        val keyShare = if (withX25519Share) be16(0x0033) + be16(2 + 4 + 32) + be16(4 + 32) + be16(0x001d) + be16(32) + ByteArray(32) else ByteArray(0)
        val ext = keyShare
        val body = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x03, 0x03))
            write(ByteArray(32)) // random, patched below
            write(0x20); write(Proto.randomBytes(32)) // session id
            write(be16(2)); write(be16(0x1302)) // one cipher suite: TLS_AES_256_GCM_SHA384
            write(1); write(0) // compression
            write(be16(ext.size)); write(ext)
        }.toByteArray()
        val hs = byteArrayOf(0x01, (body.size shr 16).toByte(), (body.size shr 8).toByte(), body.size.toByte()) + body
        val rec = byteArrayOf(0x16, 0x03, 0x01) + be16(hs.size) + hs
        val expected = hmac(secret, rec)
        val random = expected.copyOf()
        for (i in 0 until 4) random[28 + i] = (expected[28 + i].toInt() xor ((ts shr (8 * i)).toInt() and 0xFF)).toByte()
        System.arraycopy(random, 0, rec, 11, 32)
        return rec
    }

    @Test
    fun clientHelloVerifiesOnlyWithSecretAndFreshTimestamp() {
        val now = System.currentTimeMillis() / 1000
        val hello = clientHello(secret, now)
        val v = FakeTls.verifyClientHello(hello, secret)
        assertNotNull(v)
        assertEquals(now, v!!.timestamp)
        assertEquals(32, v.sessionId.size)
        assertNull(FakeTls.verifyClientHello(hello, Proto.randomBytes(16)))
        assertNull(FakeTls.verifyClientHello(clientHello(secret, now - 500), secret)) // outside tolerance
        assertNull(FakeTls.verifyClientHello(hello.copyOf(30), secret))
    }

    @Test
    fun replayCacheRejectsSecondUseUntilItExpires() {
        val cache = FakeTls.ReplayCache(windowMs = 1000, size = 4)
        val r = Proto.randomBytes(32)
        assertTrue(cache.firstSeen(r, nowMs = 0))
        assertFalse(cache.firstSeen(r, nowMs = 500))
        assertTrue(cache.firstSeen(r, nowMs = 1500))
    }

    @Test
    fun serverHelloIsHmacdOverTheWholeFlight() {
        val now = System.currentTimeMillis() / 1000
        val hello = clientHello(secret, now)
        val v = FakeTls.verifyClientHello(hello, secret)!!
        val info = FakeTls.parseClientHello(hello)
        assertEquals(setOf(0x1302), info.cipherSuites)
        assertEquals(mapOf(0x001d to 32), info.keyShares)

        val flight = FakeTls.buildServerHello(secret, v.clientRandom, v.sessionId, info)
        // records: ServerHello, CCS, one ApplicationData
        assertEquals(0x16, flight[0].toInt())
        val shLen = ((flight[3].toInt() and 0xFF) shl 8) or (flight[4].toInt() and 0xFF)
        val ccs = 5 + shLen
        assertEquals(0x14, flight[ccs].toInt())
        assertEquals(0x17, flight[ccs + 6].toInt())
        val appLen = ((flight[ccs + 9].toInt() and 0xFF) shl 8) or (flight[ccs + 10].toInt() and 0xFF)
        assertTrue(appLen in 64..160)
        assertEquals(ccs + 11 + appLen, flight.size)

        val zeroed = flight.copyOf()
        java.util.Arrays.fill(zeroed, 11, 43, 0)
        assertArrayEquals(hmac(secret, v.clientRandom, zeroed), flight.copyOfRange(11, 43))
        // the negotiated suite is the one the client offered
        assertEquals(0x1302, ((flight[43 + 1 + 32 + 0 ].toInt() and 0xFF) shl 8) or (flight[43 + 1 + 32 + 1].toInt() and 0xFF))
    }

    @Test
    fun fakeTlsStreamCarriesPayloadAndSkipsCcs() {
        val payload = Proto.randomBytes(40_000) // spans three 16 KiB records
        val wire = ByteArrayOutputStream()
        wire.write(byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)) // CCS first, must be skipped
        FakeTls.Output(wire).write(payload)
        val input = FakeTls.Input(ByteArrayInputStream(wire.toByteArray()))
        val got = ByteArray(payload.size)
        var off = 0
        while (off < got.size) {
            val n = input.read(got, off, got.size - off)
            assertTrue(n > 0)
            off += n
        }
        assertArrayEquals(payload, got)
        assertEquals(-1, input.read())
    }

    @Test
    fun firstAppdataRecordLenWalksTheFlight() {
        val sh = byteArrayOf(0x16, 3, 3, 0, 2, 9, 9)
        val ccs = byteArrayOf(0x14, 3, 3, 0, 1, 1)
        val app = byteArrayOf(0x17, 3, 3, 0x01, 0x00) // 256-byte record (body not needed to read its length)
        assertNull(FakeTls.firstAppdataRecordLen(sh))
        assertNull(FakeTls.firstAppdataRecordLen(sh + ccs))
        assertEquals(256, FakeTls.firstAppdataRecordLen(sh + ccs + app))
        assertEquals(0, FakeTls.firstAppdataRecordLen(byteArrayOf(0x15, 3, 3, 0, 2, 2, 40)))
    }

    private fun roundTrip(tag: Int, frame: ByteArray, expectBody: ByteArray) {
        val key = Proto.randomBytes(32)
        val iv = Proto.randomBytes(16)
        val wire = Ctr(key, iv).update(frame)
        val (body, _) = H2Framing.readPacket(ByteArrayInputStream(wire), Ctr(key, iv), tag)
        assertArrayEquals(expectBody, body)
    }

    @Test
    fun nativePacketsParseForEveryTransport() {
        val body = Proto.randomBytes(40).also { it[0] = 1 } // encrypted MTProto: auth_key_id != 0
        roundTrip(Proto.ABRIDGED, byteArrayOf(10) + body, body) // 10 words
        roundTrip(Proto.INTERMEDIATE, byteArrayOf(40, 0, 0, 0) + body, body)
        roundTrip(Proto.PADDED, byteArrayOf(43, 0, 0, 0) + body + byteArrayOf(7, 7, 7), body) // 3 bytes padding
    }

    @Test
    fun repliesAreFramedAndParseBack() {
        // an encrypted MTProto packet is 24 header bytes plus a multiple of 16
        val body = Proto.randomBytes(24 + 3 * 16).also { it[0] = 1 }
        for (tag in listOf(Proto.ABRIDGED, Proto.INTERMEDIATE, Proto.PADDED)) {
            val framed = H2Framing.encodeReply(body, tag)
            // readPacket decrypts, so feed it the framed bytes encrypted with the same keystream
            val key = Proto.randomBytes(32)
            val iv = Proto.randomBytes(16)
            val wire = Ctr(key, iv).update(framed)
            val (parsed, _) = H2Framing.readPacket(ByteArrayInputStream(wire), Ctr(key, iv), tag)
            assertArrayEquals("tag=$tag", body, parsed)
        }
    }

    @Test
    fun linksUseDdWithoutFakeTlsAndEeWithIt() {
        val s = "00112233445566778899aabbccddeeff"
        assertEquals("tg://proxy?server=127.0.0.1&port=1443&secret=dd$s", proxyLink("127.0.0.1", 1443, s))
        assertEquals(
            "tg://proxy?server=127.0.0.1&port=1443&secret=ee$s" + "6578616d706c652e636f6d",
            proxyLink("127.0.0.1", 1443, s, "example.com"),
        )
        assertEquals(proxyLink("127.0.0.1", 1443, s, "example.com"), ProxyConfig(secretHex = s, fakeTlsDomain = "example.com").link)
    }

    @Test
    fun proxyProtocolLineYieldsClientAddress() {
        assertEquals("1.2.3.4:5555", parseProxyLine("PROXY TCP4 1.2.3.4 10.0.0.1 5555 443\r"))
        assertEquals("", parseProxyLine("PROXY UNKNOWN"))
        assertNull(parseProxyLine("GET / HTTP/1.1"))
    }

    @Test
    fun h2NeedsCloudflareTlsAndRealDatacenters() {
        val s = "00112233445566778899aabbccddeeff"
        assertTrue(ProxyConfig(secretHex = s).h2Enabled)
        assertFalse(ProxyConfig(secretHex = s, cfFallback = false).h2Enabled)
        assertFalse(ProxyConfig(secretHex = s, disableSecure = true).h2Enabled)
        assertFalse(ProxyConfig(secretHex = s, forceTestDc = true).h2Enabled)
        assertEquals("149.154.167.40", Proto.DC_TEST_IPS[2])
        assertEquals("/apiws_test", Proto.WS_PATH_TEST)
    }
}
