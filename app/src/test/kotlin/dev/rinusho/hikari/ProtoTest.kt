package dev.rinusho.hikari

import dev.rinusho.hikari.proxy.CfDomains
import dev.rinusho.hikari.proxy.Ctr
import dev.rinusho.hikari.proxy.Handshake
import dev.rinusho.hikari.proxy.MsgSplitter
import dev.rinusho.hikari.proxy.Proto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** Plays both Telegram client and Telegram server around the proxy's crypto context. */
class ProtoTest {
    private val secret = Proto.randomBytes(16)

    /** What a Telegram client sends: 64-byte obfuscated2 init, plus its running send/receive ciphers. */
    private class FakeClient(secret: ByteArray, tag: Int, dcIdx: Int) {
        val init: ByteArray
        val send: Ctr
        val recv: Ctr
        val prekeyIv: ByteArray

        init {
            val rnd = Proto.randomBytes(64)
            rnd[0] = 0x11
            rnd[4] = 1
            val t = Proto.tagBytes(tag)
            System.arraycopy(t, 0, rnd, 56, 4)
            rnd[60] = dcIdx.toByte()
            rnd[61] = (dcIdx shr 8).toByte()
            prekeyIv = rnd.copyOfRange(8, 56)
            send = Ctr(Proto.sha256(prekeyIv.copyOfRange(0, 32), secret), prekeyIv.copyOfRange(32, 48))
            val enc = send.update(rnd)
            init = rnd.copyOf()
            System.arraycopy(enc, 56, init, 56, 8)
            val rev = prekeyIv.reversedArray()
            recv = Ctr(Proto.sha256(rev.copyOfRange(0, 32), secret), rev.copyOfRange(32, 48))
        }
    }

    @Test
    fun handshakeParsesDcAndTag() {
        for ((tag, idx) in listOf(Proto.PADDED to 2, Proto.ABRIDGED to -4, Proto.INTERMEDIATE to 5)) {
            val c = FakeClient(secret, tag, idx)
            val r = Handshake.tryHandshake(c.init, secret)
            assertNotNull(r)
            assertEquals(kotlin.math.abs(idx), r!!.dc)
            assertEquals(idx < 0, r.isMedia)
            assertEquals(tag, r.protoTag)
        }
    }

    @Test
    fun wrongSecretIsRejected() {
        val c = FakeClient(secret, Proto.PADDED, 2)
        assertNull(Handshake.tryHandshake(c.init, Proto.randomBytes(16)))
    }

    @Test
    fun relayInitCarriesTagAndDc() {
        val relay = Handshake.generateRelayInit(Proto.PADDED, -3)
        val dec = Ctr(relay.copyOfRange(8, 40), relay.copyOfRange(40, 56)).update(relay)
        assertEquals(Proto.PADDED, Proto.intAt(dec, 56))
        val idx = ((dec[60].toInt() and 0xFF) or ((dec[61].toInt() and 0xFF) shl 8)).toShort().toInt()
        assertEquals(-3, idx)
    }

    @Test
    fun dataSurvivesBothDirections() {
        val c = FakeClient(secret, Proto.PADDED, 2)
        val init = Handshake.tryHandshake(c.init, secret)!!
        val relay = Handshake.generateRelayInit(init.protoTag, init.dc)
        val ctx = Handshake.buildCrypto(init.prekeyIv, secret, relay)

        // Telegram's side of the relay connection.
        val tgDecrypt = Ctr(relay.copyOfRange(8, 40), relay.copyOfRange(40, 56)).also { it.skip(64) }
        val relayRev = relay.copyOfRange(8, 56).reversedArray()
        val tgEncrypt = Ctr(relayRev.copyOfRange(0, 32), relayRev.copyOfRange(32, 48))

        repeat(5) { round ->
            // up: client -> proxy -> telegram
            val msg = Proto.randomBytes(100 + round * 700)
            val fromClient = c.send.update(msg)
            val plain = ctx.cltDec.update(fromClient)
            assertArrayEquals(msg, plain)
            val toTg = ctx.tgEnc.update(plain)
            assertArrayEquals(msg, tgDecrypt.update(toTg))

            // down: telegram -> proxy -> client
            val resp = Proto.randomBytes(50 + round * 333)
            val fromTg = tgEncrypt.update(resp)
            val toClient = ctx.cltEnc.update(ctx.tgDec.update(fromTg))
            assertArrayEquals(resp, c.recv.update(toClient))
        }
    }

    @Test
    fun splitterCutsAbridgedAndIntermediatePackets() {
        // abridged: 1-byte length header in 4-byte words
        val p1 = byteArrayOf(2) + ByteArray(8) { 1 } // 2 words
        val p2 = byteArrayOf(1) + ByteArray(4) { 2 } // 1 word
        val s = MsgSplitter(Proto.ABRIDGED)
        val all = p1 + p2
        // feed in awkward pieces; plain == cipher here since the splitter only reads `plain`
        val first = s.split(all.copyOfRange(0, 6), all.copyOfRange(0, 6))
        assertEquals(0, first.size)
        val rest = s.split(all.copyOfRange(6, all.size), all.copyOfRange(6, all.size))
        assertEquals(2, rest.size)
        assertArrayEquals(p1, rest[0])
        assertArrayEquals(p2, rest[1])

        // intermediate: 4-byte LE length
        val q = byteArrayOf(3, 0, 0, 0, 9, 9, 9)
        val s2 = MsgSplitter(Proto.INTERMEDIATE)
        val parts = s2.split(q + q, q + q)
        assertEquals(2, parts.size)
        assertArrayEquals(q, parts[0])
    }

    @Test
    fun cfDomainDecodeMatchesUpstreamScheme() {
        // 'virkgj.com' has 6 letters -> shift each letter back by 6, suffix becomes .co.uk
        assertEquals("pclead.co.uk", CfDomains.decode("virkgj.com"))
        assertEquals(true, CfDomains.defaults.all(CfDomains::isValid))
    }
}
