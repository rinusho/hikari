package dev.rinusho.hikari.proxy

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

const val DEFAULT_PORT = 1443
const val DEFAULT_DC_IPS = "2:149.154.167.220\n4:149.154.167.220"

/** Immutable runtime configuration handed to the engine. */
data class ProxyConfig(
    val host: String = "127.0.0.1",
    val port: Int = DEFAULT_PORT,
    val secretHex: String,
    val dcRedirects: Map<Int, String> = mapOf(2 to "149.154.167.220", 4 to "149.154.167.220"),
    val poolSize: Int = 4,
    val cfFallback: Boolean = true,
    val cfUserDomains: List<String> = emptyList(),
) {
    val dcLink: String get() = "tg://proxy?server=$host&port=$port&secret=dd$secretHex"
}

fun parseDcIps(text: String): Result<Map<Int, String>> = runCatching {
    val out = LinkedHashMap<Int, String>()
    for (raw in text.split('\n', ',', ';', ' ')) {
        val e = raw.trim()
        if (e.isEmpty()) continue
        val (dc, ip) = e.split(':', limit = 2).also { require(it.size == 2) { "Invalid entry: $e" } }
        val parts = ip.split('.')
        require(parts.size == 4 && parts.all { p -> p.toIntOrNull()?.let { it in 0..255 } == true }) { "Invalid IPv4: $ip" }
        out[dc.trim().toInt()] = ip.trim()
    }
    out
}

fun parseDomains(text: String): List<String> =
    text.split('\n', ',', ';', ' ').map { it.trim() }.filter { it.isNotEmpty() }.distinctBy { it.lowercase() }

fun randomSecretHex(): String = Proto.hex(Proto.randomBytes(16))

// ───────────────────────────── Cloudflare proxy domains (port of config.py / balancer.py)

object CfDomains {
    private const val LIST_URL =
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"
    private const val MIN_VALID = 3

    private val ENCODED = listOf(
        "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
        "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
        "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
        "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
    )

    /** Same Caesar-style decoding as upstream `_dd`: shift back by the number of letters, `.com` -> `.co.uk`. */
    fun decode(s: String): String {
        if (!s.endsWith(".com")) return s
        val p = s.dropLast(4)
        val n = p.count { it.isLetter() }
        val sb = StringBuilder()
        for (c in p) {
            if (c.isLetter()) {
                val base = if (c > '`') 'a'.code else 'A'.code
                sb.append(Char(((c.code - base - n) % 26 + 26) % 26 + base))
            } else sb.append(c)
        }
        return sb.append(".co.uk").toString()
    }

    val defaults: List<String> get() = ENCODED.map(::decode)

    fun isValid(d: String): Boolean {
        if (d.isEmpty() || d.length > 253 || d.startsWith('.') || d.endsWith('.')) return false
        val labels = d.split('.')
        if (labels.size < 2) return false
        for (l in labels) {
            if (l.isEmpty() || l.length > 63 || l.startsWith('-') || l.endsWith('-')) return false
            if (!l.all { it.isLetterOrDigit() || it == '-' }) return false
        }
        val tld = labels.last()
        return tld.length >= 2 && tld.any { it.isLetter() }
    }

    /** Fetches the community-maintained list; returns null on any failure. */
    fun fetch(): List<String>? = runCatching {
        val c = URL("$LIST_URL?${System.nanoTime()}").openConnection() as HttpURLConnection
        c.connectTimeout = 10_000
        c.readTimeout = 10_000
        c.setRequestProperty("User-Agent", "tg-ws-proxy-android")
        val text = c.inputStream.bufferedReader().use { it.readText() }
        c.disconnect()
        text.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith('#') }
            .map { decode(it).lowercase() }.filter(::isValid).distinct()
            .takeIf { it.size >= MIN_VALID }
    }.getOrNull()
}

class Balancer {
    @Volatile private var domains: List<String> = emptyList()
    private val dcToDomain = java.util.concurrent.ConcurrentHashMap<Int, String>()

    fun update(list: List<String>) {
        if (list.isEmpty() || list.toSet() == domains.toSet()) return
        domains = list.toList()
        dcToDomain.clear()
        for (dc in intArrayOf(1, 2, 3, 4, 5, 203)) dcToDomain[dc] = domains.random()
    }

    fun setActive(dc: Int, domain: String): Boolean = dcToDomain.put(dc, domain) != domain

    fun domainsFor(dc: Int): List<String> {
        val cur = dcToDomain[dc]
        val rest = domains.filter { it != cur }.shuffled()
        return if (cur != null) listOf(cur) + rest else rest
    }
}

// ───────────────────────────── Stats & log

object ProxyStats {
    val total = AtomicLong()
    val active = AtomicLong()
    val ws = AtomicLong()
    val cf = AtomicLong()
    val tcp = AtomicLong()
    val bad = AtomicLong()
    val up = AtomicLong()
    val down = AtomicLong()
    val poolHits = AtomicLong()
    val poolMisses = AtomicLong()

    data class Snapshot(
        val total: Long, val active: Long, val ws: Long, val cf: Long, val tcp: Long,
        val bad: Long, val up: Long, val down: Long, val poolHits: Long, val poolMisses: Long,
    )

    fun snapshot() = Snapshot(
        total.get(), active.get(), ws.get(), cf.get(), tcp.get(), bad.get(),
        up.get(), down.get(), poolHits.get(), poolMisses.get(),
    )

    fun reset() {
        listOf(total, active, ws, cf, tcp, bad, up, down, poolHits, poolMisses).forEach { it.set(0) }
    }
}

object ProxyLog {
    private const val MAX = 400
    private val fmt = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines

    private fun add(level: Char, msg: String) {
        val line = "${fmt.format(java.util.Date())} $level $msg"
        _lines.update { (it + line).takeLast(MAX) }
    }

    fun i(msg: String) { android.util.Log.i("tg-ws-proxy", msg); add('I', msg) }
    fun w(msg: String) { android.util.Log.w("tg-ws-proxy", msg); add('W', msg) }
    fun d(msg: String) { android.util.Log.d("tg-ws-proxy", msg) }
    fun clear() { _lines.value = emptyList() }
}
