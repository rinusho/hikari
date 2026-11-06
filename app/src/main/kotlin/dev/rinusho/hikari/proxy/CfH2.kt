package dev.rinusho.hikari.proxy

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Proxy
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Dispatcher
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/*
 * HTTP/2 media multiplexing, port of proxy/cf_h2.py + h2_transport.py.
 *
 * Instead of one WebSocket per media connection, MTProto packets of media DCs are POSTed as
 * `application/octet-stream` to https://kws{dc}.{cf-domain}/api and the reply body is the answer.
 * Many native connections share a few HTTP/2 connections ("lanes"). Because HTTP has no push,
 * a recovery loop replays the last packets when no answer arrives (MTProto de-duplicates them).
 * The HTTP/2 framing itself is delegated to OkHttp; everything above it is a direct port.
 */

private const val MAX_PACKET = 4 * 1024 * 1024
private const val MAX_PLAIN_PADDING = 256
private const val MAX_CHANNEL_REQUESTS = 8
private const val MAX_CHANNEL_BYTES = 8L * 1024 * 1024
private const val MAX_LANE_REQUESTS = 64
private const val MAX_LANE_BYTES = 32L * 1024 * 1024
private const val MAX_LANE_REPLY_BYTES = 32L * 1024 * 1024
private const val DOMAIN_COOLDOWN = 30.0
private const val REQUEST_TIMEOUT = 65.0
private const val SETUP_TIMEOUT_MS = 8000L
private const val REPLAY_IDLE_SECONDS = 1.0
private const val REPLAY_REQUEST_SECONDS = 3.0
private const val REPLAY_CHECK_MS = 250L
private const val REPLAY_MAX_AGE = 30.0
private const val REPLAY_HISTORY_BYTES = 64 * 1024
private const val REPLAY_HISTORY_PACKETS = 16
private const val MAX_CHANNEL_REPLAYS = 2
private const val REPLAY_SLOT_SECONDS = 30.0
private const val REPLAY_RETRY_SECONDS = 2.0
private const val REPLAY_MAX_ATTEMPTS = 3

private fun now(): Double = System.nanoTime() / 1e9

/** An endpoint error the native client must receive as a 4-byte negative code, not just EOF. */
class MTProtoTransportError(val code: Int, source: String) : IOException("$code ($source)")

private class ReplyBufferFull(msg: String) : IOException(msg)
class NativeDeliveryError(msg: String, cause: Throwable? = null) : IOException(msg, cause)

// ───────────────────────────── MTProto packet framing

private fun readFully(input: InputStream, n: Int): ByteArray {
    val b = ByteArray(n)
    var got = 0
    while (got < n) {
        val r = input.read(b, got, n - got)
        if (r < 0) throw java.io.EOFException("native eof")
        got += r
    }
    return b
}

private fun le32(b: ByteArray, off: Int): Long =
    (b[off].toLong() and 0xFF) or ((b[off + 1].toLong() and 0xFF) shl 8) or
        ((b[off + 2].toLong() and 0xFF) shl 16) or ((b[off + 3].toLong() and 0xFF) shl 24)

object H2Framing {
    /** Reads one transport packet from the native client; returns (MTProto body, quick-ack flag). */
    fun readPacket(input: InputStream, dec: Ctr, tag: Int): Pair<ByteArray, Boolean> {
        fun plain(n: Int) = dec.update(readFully(input, n))
        val quick: Boolean
        val length: Long
        if (tag == Proto.ABRIDGED) {
            val first = plain(1)[0].toInt() and 0xFF
            quick = first and 0x80 != 0
            var words = (first and 0x7f).toLong()
            if (words == 0x7fL) words = le32(plain(3) + byteArrayOf(0), 0)
            length = words * 4
        } else {
            val v = le32(plain(4), 0)
            quick = v and 0x80000000L != 0L
            length = v and 0x7fffffffL
        }
        val padded = tag == Proto.PADDED
        require(length in 24..(MAX_PACKET + if (padded) MAX_PLAIN_PADDING else 0).toLong()) {
            "native packet length outside supported range: $length"
        }
        var body = plain(length.toInt())
        if (padded) {
            val packetLength: Long
            val maxPadding: Int
            if (body.copyOf(8).all { it.toInt() == 0 }) {
                packetLength = 20 + le32(body, 16)
                maxPadding = MAX_PLAIN_PADDING
            } else {
                packetLength = 24 + ((length - 24) / 16) * 16
                maxPadding = 15
            }
            val padding = length - packetLength
            require(packetLength in 24..length && padding <= maxPadding) {
                "invalid padded native packet: frame=$length packet=$packetLength padding=$padding limit=$maxPadding"
            }
            body = body.copyOf(packetLength.toInt())
        }
        require(body.size % 4 == 0 && body.size <= MAX_PACKET) { "invalid native packet alignment or size" }
        return body to quick
    }

    /** Wraps an HTTP reply body into the transport framing the native client negotiated. */
    fun encodeReply(body: ByteArray, tag: Int): ByteArray {
        require(body.isNotEmpty() && body.size % 4 == 0 && body.size <= MAX_PACKET) {
            "invalid HTTP MTProto response length: ${body.size}"
        }
        if (tag == Proto.ABRIDGED) {
            val words = body.size / 4
            val prefix = if (words < 0x7f) byteArrayOf(words.toByte())
            else byteArrayOf(0x7f, words.toByte(), (words shr 8).toByte(), (words shr 16).toByte())
            return prefix + body
        }
        val padding = if (tag == Proto.PADDED) Proto.randomBytes(Proto.randomBytes(1)[0].toInt().and(0xFF) % 4) else ByteArray(0)
        val len = body.size + padding.size
        return byteArrayOf(len.toByte(), (len shr 8).toByte(), (len shr 16).toByte(), (len shr 24).toByte()) + body + padding
    }
}

// ───────────────────────────── replay bookkeeping

private class ReplayPacket(val sentAt: Double, val body: ByteArray, val sequence: Int) {
    var attempts = 0
    var lastAttemptAt = 0.0
    var pending: Job? = null
    val originals = HashSet<Job>()
    var retired = false
    var replyId: String? = null
    val replayed get() = lastAttemptAt > 0 || attempts > 0
}

private suspend fun Call.await(): Response = suspendCancellableCoroutine { c ->
    c.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) { c.resumeWithException(e) }
        override fun onResponse(call: Call, response: Response) { c.resume(response) }
    })
}

// ───────────────────────────── lane: one HTTP/2 client talking to one CF host

class H2Lane(val host: String, val id: Int, private val scope: CoroutineScope) {
    val channels: MutableSet<H2Channel> = ConcurrentHashMap.newKeySet()
    @Volatile var failedUntil = 0.0
    @Volatile var closed = false
    private val lock = Any()
    private var inflight = 0
    private var queuedBytes = 0L
    private var replyBufferBytes = 0L

    private val client: OkHttpClient = OkHttpClient.Builder()
        .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .proxy(Proxy.NO_PROXY)
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(REQUEST_TIMEOUT.toLong(), TimeUnit.SECONDS)
        .writeTimeout(REQUEST_TIMEOUT.toLong(), TimeUnit.SECONDS)
        .dispatcher(Dispatcher().apply { maxRequests = MAX_LANE_REQUESTS; maxRequestsPerHost = MAX_LANE_REQUESTS })
        .build()

    /** HEAD /api must come back over HTTP/2 with a sane status before the lane is used. */
    suspend fun preflight() {
        val call = client.newCall(Request.Builder().url("https://$host/api").head().build())
        call.await().use { r ->
            if (r.protocol != Protocol.HTTP_2) throw IOException("CF /api preflight negotiated ${r.protocol}")
            if (r.code !in 200..299 && r.code != 405 && r.code != 501) {
                throw IOException("CF /api preflight HTTP ${r.code} cf_ray=${r.header("cf-ray") ?: "-"}")
            }
        }
    }

    fun hasCapacity(length: Int) = synchronized(lock) { inflight < MAX_LANE_REQUESTS && queuedBytes + length <= MAX_LANE_BYTES }

    suspend fun reserve(length: Int, wait: Boolean): Boolean {
        val deadline = now() + REQUEST_TIMEOUT
        while (true) {
            synchronized(lock) {
                if (closed) throw IOException("H2 lane closed")
                if (inflight < MAX_LANE_REQUESTS && queuedBytes + length <= MAX_LANE_BYTES) {
                    inflight++; queuedBytes += length
                    return true
                }
            }
            if (!wait) return false
            if (now() > deadline) throw IOException("H2 lane capacity wait timed out")
            delay(20)
        }
    }

    fun release(length: Int) = synchronized(lock) { inflight--; queuedBytes -= length }

    /** POSTs one MTProto packet and returns the reply body (possibly empty). */
    suspend fun post(body: ByteArray, replay: Boolean, channel: H2Channel?): ByteArray {
        ProxyLog.d("H2 lane=$id POST ${body.size} bytes replay=$replay")
        val job = currentCoroutineContext()[Job]!!
        val request = Request.Builder().url("https://$host/api")
            .header("Accept-Encoding", "identity")
            .post(object : RequestBody() {
                override fun contentType() = "application/octet-stream".toMediaType()
                override fun contentLength() = body.size.toLong()
                override fun writeTo(sink: BufferedSink) {
                    sink.write(body); sink.flush()
                    channel?.markSent(job)
                }
            }).build()
        val call = client.newCall(request)
        var buffered = 0L
        var receiving = false
        try {
            return coroutineScope {
                // blocking reads cannot be interrupted by coroutine cancellation, so cancel the call itself
                val watcher = launch { try { awaitCancellation() } finally { call.cancel() } }
                try {
                    call.await().use { r ->
                        if (r.protocol != Protocol.HTTP_2) throw IOException("CF /api downgraded to ${r.protocol}")
                        val ray = r.header("cf-ray") ?: "-"
                        when (r.code) {
                            403, 404, 429, 444 -> throw MTProtoTransportError(-r.code, "HTTP ${r.code} cf_ray=$ray")
                            200 -> Unit
                            else -> throw IOException("CF /api HTTP ${r.code} cf_ray=$ray")
                        }
                        if (r.header("content-type")?.contains("text/html", ignoreCase = true) == true) {
                            throw IOException("CF /api returned HTML instead of MTProto")
                        }
                        channel?.responseStarted(job)
                        receiving = true
                        val declared = r.header("content-length")?.toLongOrNull()
                        if (declared != null && declared !in 0..MAX_PACKET.toLong()) {
                            throw IOException("H2 response Content-Length exceeds native packet bound")
                        }
                        val content = ByteArrayOutputStream()
                        val src = r.body!!.source()
                        val buf = ByteArray(16384)
                        while (true) {
                            val n = src.read(buf)
                            if (n < 0) break
                            if (content.size() + n > MAX_PACKET) throw IOException("H2 response exceeds native packet bound")
                            synchronized(lock) {
                                if (replyBufferBytes + n > MAX_LANE_REPLY_BYTES) throw ReplyBufferFull("H2 lane response buffers exceeded bound")
                                replyBufferBytes += n
                            }
                            buffered += n
                            content.write(buf, 0, n)
                            channel?.lastProgress = now()
                        }
                        val bytes = content.toByteArray()
                        if (declared != null && bytes.size.toLong() != declared) throw IOException("incomplete H2 response body")
                        if (bytes.isNotEmpty() && bytes.size % 4 != 0) throw IOException("CF /api response is not an aligned MTProto packet")
                        if (bytes.size == 4) {
                            val code = le32(bytes, 0).toInt()
                            if (code < 0) throw MTProtoTransportError(code, "HTTP 200 payload")
                        }
                        bytes
                    }
                } finally {
                    watcher.cancel()
                }
            }
        } catch (e: MTProtoTransportError) {
            throw e
        } catch (e: ReplyBufferFull) {
            throw e
        } catch (e: IOException) {
            currentCoroutineContext().ensureActive()
            failedUntil = now() + DOMAIN_COOLDOWN
            throw e
        } finally {
            synchronized(lock) { replyBufferBytes -= buffered }
            if (receiving) channel?.responseDone(job)
        }
    }

    suspend fun close() {
        closed = true
        channels.toList().forEach { it.close() }
        client.dispatcher.cancelAll()
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
        ProxyLog.d("H2 lane=$id closed host=$host")
    }
}

// ───────────────────────────── channel: one native connection mapped onto POSTs

class H2Channel(
    private val lane: H2Lane, val id: Int, val label: String, private val scope: CoroutineScope,
) {
    private val st = Any()
    @Volatile var closed = false
    @Volatile var transportError: Int? = null
    @Volatile var lastProgress = now()
    @Volatile var deliveringSince: Double? = null
    private val pending = LinkedHashMap<Job, Int>()
    private val pendingSince = HashMap<Job, Double>()
    private val sentSince = HashMap<Job, Double>()
    private val receivingTasks = HashSet<Job>()
    private val replayPending = HashSet<Job>()
    private val replayHistory = ArrayList<ReplayPacket>()
    private var replayKey: ByteArray? = null
    private var pendingBytes = 0L
    private val replyBytes = java.util.concurrent.atomic.AtomicLong()
    private val queue = Channel<Any>(16)
    private val wakeup = Channel<Unit>(Channel.CONFLATED)
    private val sendLock = Mutex()
    private val closeLock = Mutex()
    private var closeDone = false
    @Volatile private var uploadWaitSince: Double? = null
    @Volatile private var uploadWaitPhase = "-"
    @Volatile private var uploadWaitBytes = 0
    private var requests = 0
    var down = 0L

    init { lane.channels.add(this) }

    private val nativeBackpressure get() = replyBytes.get() > 0 || deliveringSince != null

    fun markSent(job: Job) = synchronized(st) { sentSince[job] = now() }
    fun responseStarted(job: Job) = synchronized(st) { receivingTasks.add(job); lastProgress = now() }
    fun responseDone(job: Job) { synchronized(st) { receivingTasks.remove(job) } }

    private fun hasCapacity(length: Int) =
        synchronized(st) { pending.size < MAX_CHANNEL_REQUESTS && pendingBytes + length <= MAX_CHANNEL_BYTES }

    fun wakeReceiver() {
        val idle = synchronized(st) { pending.isEmpty() }
        if (!closed && idle && !nativeBackpressure) wakeup.trySend(Unit)
    }

    private fun overdueOriginal(e: ReplayPacket, t: Double) = synchronized(st) {
        e.retired || e.originals.any { it in sentSince && it !in receivingTasks && t - sentSince.getValue(it) >= REPLAY_REQUEST_SECONDS }
    }

    private fun replayLimit(e: ReplayPacket) = synchronized(st) {
        if (e.originals.isNotEmpty() || e.retired || e === replayHistory.lastOrNull()) REPLAY_MAX_ATTEMPTS else 0
    }

    private fun capacityCandidate(t: Double): Pair<Job, ReplayPacket?>? = synchronized(st) {
        val ordered = sentSince.entries.sortedWith(compareBy({ it.key !in replayPending }, { it.value }))
        for ((job, sent) in ordered) {
            if (job.isCompleted || job in receivingTasks || t - sent < REPLAY_REQUEST_SECONDS) continue
            if (job in replayPending) return@synchronized job to null
            val entry = replayHistory.firstOrNull { job in it.originals }
            if (entry != null && t - entry.sentAt <= REPLAY_MAX_AGE) return@synchronized job to entry
        }
        null
    }

    /** Frees a slot by cancelling the oldest request that is stuck waiting for its answer. */
    private suspend fun makeUploadRoom(t: Double) {
        if (closed || uploadWaitSince == null) return
        val candidates: List<H2Channel> = when (uploadWaitPhase) {
            "channel-capacity" -> if (hasCapacity(uploadWaitBytes)) return else listOf(this)
            "lane-capacity" -> if (lane.hasCapacity(uploadWaitBytes)) return else
                lane.channels.sortedBy { c -> synchronized(c.st) { c.sentSince.values.minOrNull() ?: t } }
            else -> return
        }
        for (ch in candidates) {
            val (job, entry) = ch.capacityCandidate(t) ?: continue
            synchronized(ch.st) { ch.sentSince.remove(job); entry?.retired = true }
            job.cancel()
            job.join()
            return
        }
    }

    private fun replayBlocker(e: ReplayPacket, t: Double): String? = synchronized(st) {
        if (t - e.sentAt !in 0.0..REPLAY_MAX_AGE) return@synchronized "expired"
        if (e.attempts >= replayLimit(e)) return@synchronized "budget-used"
        if (nativeBackpressure) return@synchronized "native-backpressure"
        if (e.originals.any { it in receivingTasks }) return@synchronized "original-body"
        val replayJob = e.pending
        if (replayJob != null && replayJob in receivingTasks) return@synchronized "replay-body"
        if (e.replayed && t - e.lastAttemptAt < REPLAY_RETRY_SECONDS) return@synchronized "backoff-or-progress"
        if (overdueOriginal(e, t)) return@synchronized null
        if (e !== replayHistory.lastOrNull() || pending.keys.any { it !== e.pending }) return@synchronized "receiver-active"
        if (e.replayed && t - lastProgress < REPLAY_IDLE_SECONDS) return@synchronized "backoff-or-progress"
        null
    }

    fun fail(error: Throwable) {
        synchronized(st) {
            if (closed) return
            if (error is MTProtoTransportError) transportError = error.code
            closed = true
        }
        wakeup.trySend(Unit)
        while (queue.tryReceive().isSuccess) { /* drop undelivered replies */ }
        replyBytes.set(0)
        queue.trySend(error)
    }

    /** Queues one native packet as an HTTP POST. Replays return false when they must be skipped. */
    suspend fun send(body: ByteArray, quick: Boolean, replay: Boolean = false): Boolean {
        if (replay && sendLock.isLocked) return false
        if (!replay) { uploadWaitSince = now(); uploadWaitPhase = "send-lock"; uploadWaitBytes = body.size }
        try {
            return sendLock.withLock { sendLocked(body, replay) }
        } finally {
            if (!replay) { uploadWaitSince = null; uploadWaitPhase = "-"; uploadWaitBytes = 0 }
        }
    }

    private suspend fun sendLocked(body: ByteArray, replay: Boolean): Boolean {
        if (replay) {
            if (!hasCapacity(body.size)) return false
        } else {
            uploadWaitPhase = "channel-capacity"
            val deadline = now() + REQUEST_TIMEOUT
            while (!closed && !hasCapacity(body.size)) {
                if (now() > deadline) throw IOException("H2 channel capacity wait timed out")
                delay(20)
            }
        }
        if (closed) throw IOException("H2 channel closed")
        if (!replay) uploadWaitPhase = "lane-capacity"
        if (!lane.reserve(body.size, wait = !replay)) return false
        if (closed) { lane.release(body.size); throw IOException("H2 channel closed") }

        val t = now()
        val replayPacket = if (replay) synchronized(st) { findPacket(body) } else null
        if (replay && (replayPacket == null || replayPacket.pending != null || replayBlocker(replayPacket, t) != null)) {
            lane.release(body.size)
            return false
        }

        val nativePacket: ReplayPacket?
        val job: Job
        synchronized(st) {
            pendingBytes += body.size
            requests++
            ProxyStats.up.addAndGet(body.size.toLong())
            nativePacket = if (!replay) rememberPacket(body, t) else null
            val packet = replayPacket ?: nativePacket
            job = scope.launch(start = CoroutineStart.LAZY) { runRequest(body, replay, packet) }
            pending[job] = body.size
            pendingSince[job] = t
            nativePacket?.originals?.add(job)
            if (nativePacket != null) trimHistory(t)
            if (replay) {
                replayPending.add(job)
                replayPacket!!.attempts++
                replayPacket.lastAttemptAt = t
                replayPacket.pending = job
            }
        }
        job.start()
        return true
    }

    private fun findPacket(body: ByteArray) = replayHistory.firstOrNull { it.body.contentEquals(body) }

    private fun rememberPacket(body: ByteArray, t: Double): ReplayPacket? {
        val key = body.copyOf(8)
        if (key.all { it.toInt() == 0 }) return null // unencrypted handshake packets are never replayed
        if (replayKey?.contentEquals(key) != true) { replayHistory.clear(); replayKey = key }
        if (body.size > REPLAY_HISTORY_BYTES) return null
        return findPacket(body) ?: ReplayPacket(t, body, requests).also { replayHistory.add(it) }
    }

    private fun trimHistory(t: Double) {
        var retained = replayHistory.sumOf { it.body.size }
        while (replayHistory.size > REPLAY_HISTORY_PACKETS || retained > REPLAY_HISTORY_BYTES) {
            val victim = replayHistory.firstOrNull {
                it.originals.isEmpty() && !(it.retired && it.attempts < REPLAY_MAX_ATTEMPTS && t - it.sentAt <= REPLAY_MAX_AGE)
            } ?: replayHistory[0]
            replayHistory.remove(victim)
            retained -= victim.body.size
        }
    }

    private suspend fun runRequest(body: ByteArray, replay: Boolean, packet: ReplayPacket?) {
        val job = currentCoroutineContext()[Job]!!
        try {
            val reply = lane.post(body, replay, this)
            lastProgress = now()
            if (reply.isNotEmpty() && !closed) {
                val id = Proto.hex(reply.copyOf(minOf(24, reply.size)))
                if (packet != null && id != packet.replyId) { packet.replyId = id; packet.attempts = 0 }
                if (replyBytes.get() + reply.size > MAX_CHANNEL_BYTES) throw IOException("H2 client response queue exceeded bound")
                replyBytes.addAndGet(reply.size.toLong())
                if (queue.trySend(reply).isFailure) {
                    replyBytes.addAndGet(-reply.size.toLong())
                    throw IOException("H2 client response queue exceeded bound")
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: MTProtoTransportError) {
            if (!closed) ProxyLog.w("[$label] H2 channel=$id MTProto transport error=${e.code}; reporting to client")
            fail(e)
        } catch (e: Exception) {
            if (!closed) ProxyLog.w("[$label] H2 channel=$id request failed: ${e.javaClass.simpleName}: ${e.message}")
            fail(e)
        } finally {
            withContext(NonCancellable) { finishRequest(job, packet) }
        }
    }

    private fun finishRequest(job: Job, packet: ReplayPacket?) {
        val length: Int
        synchronized(st) {
            length = pending.remove(job) ?: return
            pendingBytes -= length
            pendingSince.remove(job)
            sentSince.remove(job)
            replayPending.remove(job)
            val p = packet ?: replayHistory.firstOrNull { job in it.originals || it.pending === job }
            if (p != null) {
                p.originals.remove(job)
                if (p.pending === job) p.pending = null
            }
        }
        lane.release(length)
        wakeReceiver()
    }

    /** Replays the latest packets while no answer is arriving (MTProto de-duplicates them). */
    suspend fun recover() {
        while (!closed) {
            withTimeoutOrNull(REPLAY_CHECK_MS) { wakeup.receive() }
            val t = now()
            makeUploadRoom(t)
            if (closed || nativeBackpressure) continue
            val candidates = synchronized(st) {
                replayHistory.sortedWith(compareBy(
                    { !overdueOriginal(it, t) },
                    { if (overdueOriginal(it, t)) it.sequence else -it.sequence },
                ))
            }
            for (entry in candidates) {
                if (replayBlocker(entry, t) != null) continue
                var replace: Job? = entry.pending
                if (replace == null && synchronized(st) { replayPending.size } >= MAX_CHANNEL_REPLAYS) {
                    replace = synchronized(st) { pending.keys.firstOrNull { it in replayPending && it !in receivingTasks } }
                    if (replace == null) continue
                }
                val victim = replace
                if (victim != null) {
                    val (receiving, sent) = synchronized(st) { (victim in receivingTasks) to sentSince[victim] }
                    if (receiving || sent == null || t - sent < REPLAY_SLOT_SECONDS) continue
                    victim.cancel()
                    victim.join()
                }
                send(entry.body, quick = false, replay = true)
                break
            }
        }
    }

    suspend fun receive(): ByteArray {
        val v = queue.receive()
        if (v is Throwable) throw v
        v as ByteArray
        replyBytes.addAndGet(-v.size.toLong())
        wakeReceiver()
        return v
    }

    suspend fun close() {
        closeLock.withLock {
            if (closeDone) return
            fail(IOException("H2 channel closed"))
            closed = true
            val tasks = synchronized(st) { pending.keys.toList() }
            tasks.forEach { it.cancel() }
            tasks.forEach { it.join() }
            synchronized(st) {
                replayPending.clear(); replayHistory.clear(); sentSince.clear()
            }
            lane.channels.remove(this)
            closeDone = true
            ProxyLog.d("[$label] H2 channel=$id closed requests=$requests down=$down")
        }
    }
}

// ───────────────────────────── pool

class CfH2Pool(private val scope: CoroutineScope, private val balancer: Balancer) {
    private val lanes = ConcurrentHashMap<String, H2Lane>()
    private val locks = ConcurrentHashMap<String, Mutex>()
    private val failedUntil = ConcurrentHashMap<String, Double>()
    private val setupRetryAfter = ConcurrentHashMap<Int, Double>()
    private var nextLane = 0
    private var nextChannel = 0
    @Volatile private var closed = false

    suspend fun open(dc: Int, label: String): H2Channel? {
        if (closed) throw IOException("H2 pool closed")
        if (now() < (setupRetryAfter[dc] ?: 0.0)) return null
        return try {
            withTimeout(SETUP_TIMEOUT_MS) { openInternal(dc, label) }
        } catch (_: TimeoutCancellationException) {
            setupRetryAfter[dc] = now() + DOMAIN_COOLDOWN
            ProxyLog.w("[$label] H2 DC$dc setup timed out; using WS for ${DOMAIN_COOLDOWN.toInt()}s")
            null
        }
    }

    private suspend fun openInternal(dc: Int, label: String): H2Channel? {
        if (dc !in Proto.DC_DEFAULT_IPS) {
            ProxyLog.w("[$label] H2 unsupported DC$dc -> existing WS route")
            return null
        }
        for (base in balancer.domainsFor(dc)) {
            val host = "kws$dc.$base"
            locks.getOrPut(host) { Mutex() }.withLock {
                if (closed) throw IOException("H2 pool closed")
                var lane = lanes[host]
                if (now() < maxOf(failedUntil[host] ?: 0.0, lane?.failedUntil ?: 0.0)) return@withLock
                if (lane == null) {
                    val fresh = H2Lane(host, synchronized(this) { ++nextLane }, scope)
                    try {
                        fresh.preflight()
                    } catch (e: CancellationException) {
                        fresh.close(); throw e
                    } catch (e: IOException) {
                        failedUntil[host] = now() + DOMAIN_COOLDOWN
                        ProxyLog.w("[$label] H2 lane=${fresh.id} preflight failed host=$host: ${e.javaClass.simpleName}: ${e.message}")
                        fresh.close()
                        return@withLock
                    }
                    if (closed) { fresh.close(); throw IOException("H2 pool closed during preflight") }
                    lanes[host] = fresh
                    lane = fresh
                }
                val channel = H2Channel(lane, synchronized(this) { ++nextChannel }, label, scope)
                balancer.setActive(dc, base)
                ProxyLog.i("[$label] ROUTE DC$dc media -> H2 lane=${lane.id} channel=${channel.id} host=$host channels=${lane.channels.size}")
                return channel
            }
        }
        ProxyLog.d("[$label] H2 DC$dc unavailable; using WS")
        return null
    }

    suspend fun close() {
        closed = true
        lanes.values.toList().forEach { runCatching { it.close() } }
        lanes.clear()
    }
}

/** Runs a native connection over [channel] until either side ends. */
suspend fun bridgeH2(
    cin: InputStream, cout: OutputStream, channel: H2Channel, ctx: CryptoCtx, tag: Int, closeClient: () -> Unit,
) {
    fun writeNative(data: ByteArray) {
        try {
            cout.write(ctx.cltEnc.update(data)); cout.flush()
        } catch (e: IOException) {
            throw NativeDeliveryError(e.message ?: "native write failed", e)
        }
    }

    val done = CompletableDeferred<Throwable?>()
    try {
        coroutineScope {
            // On cancellation (service stop) the blocking read in `upload` must be unblocked by closing the socket.
            val closer = launch { try { awaitCancellation() } finally { closeClient() } }
            val upload = launch {
                try {
                    while (true) {
                        val (body, quick) = try {
                            H2Framing.readPacket(cin, ctx.cltDec, tag)
                        } catch (e: IOException) {
                            throw NativeDeliveryError(e.message ?: "native read failed", e)
                        }
                        channel.send(body, quick)
                    }
                } catch (e: Throwable) { done.complete(e) }
            }
            val download = launch {
                try {
                    while (true) {
                        val body = channel.receive()
                        if (channel.closed) throw NativeDeliveryError("H2 channel closed before native response")
                        channel.deliveringSince = now()
                        try { writeNative(H2Framing.encodeReply(body, tag)) } finally { channel.deliveringSince = null }
                        channel.down += body.size
                        ProxyStats.down.addAndGet(body.size.toLong())
                        channel.lastProgress = now()
                        channel.wakeReceiver()
                    }
                } catch (e: Throwable) { done.complete(e) }
            }
            val recover = launch {
                try { channel.recover(); done.complete(null) } catch (e: Throwable) { done.complete(e) }
            }

            val err = done.await()
            download.cancel(); recover.cancel()
            download.join(); recover.join()
            channel.transportError?.let { code ->
                runCatching {
                    writeNative(H2Framing.encodeReply(byteArrayOf(code.toByte(), (code shr 8).toByte(), (code shr 16).toByte(), (code shr 24).toByte()), tag))
                    channel.down += 4
                    ProxyStats.down.addAndGet(4)
                }
            }
            closeClient() // unblocks a pending blocking read in `upload`
            upload.cancel(); upload.join()
            closer.cancel()
            when (err) {
                null, is CancellationException -> Unit
                is NativeDeliveryError, is java.io.EOFException -> ProxyLog.d("[${channel.label}] H2 channel=${channel.id} native closed: ${err.message}")
                else -> if (!channel.closed) ProxyLog.w("[${channel.label}] H2 channel=${channel.id} bridge ended: ${err.javaClass.simpleName}: ${err.message}")
            }
        }
    } finally {
        withContext(NonCancellable) {
            closeClient()
            channel.close()
        }
    }
}
