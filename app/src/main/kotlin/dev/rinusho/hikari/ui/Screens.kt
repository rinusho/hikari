package dev.rinusho.hikari.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.Crossfade
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Article
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.Cloud
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Router
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.rinusho.hikari.MainViewModel
import dev.rinusho.hikari.R
import dev.rinusho.hikari.proxy.Proto
import dev.rinusho.hikari.proxy.parseDcIps

private val Gutter = 16.dp

@Composable
fun TgWsApp(vm: MainViewModel) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val cs = MaterialTheme.colorScheme
    val tabs: List<Pair<ImageVector, Int>> = listOf(
        Icons.Rounded.Home to R.string.tab_home,
        Icons.Rounded.Settings to R.string.tab_settings,
        Icons.AutoMirrored.Rounded.Article to R.string.tab_logs,
    )

    Box(Modifier.fillMaxSize().background(cs.surface)) {
        // Soft wash of the accent colour behind the top of every screen.
        Box(
            Modifier
                .fillMaxWidth()
                .height(380.dp)
                .background(Brush.verticalGradient(listOf(cs.primaryContainer.copy(alpha = 0.6f), Color.Transparent))),
        )
        Scaffold(
            containerColor = Color.Transparent,
            bottomBar = {
                NavigationBar(containerColor = cs.surfaceContainer, tonalElevation = 0.dp) {
                    tabs.forEachIndexed { i, (icon, label) ->
                        NavigationBarItem(
                            selected = tab == i,
                            onClick = { tab = i },
                            icon = { Icon(icon, contentDescription = null) },
                            label = { Text(stringResource(label)) },
                        )
                    }
                }
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                Header(stringResource(tabs[tab].second), tab == 0)
                Box(Modifier.weight(1f)) {
                    Crossfade(tab, label = "tab") { t ->
                        when (t) {
                            0 -> HomeScreen(vm)
                            1 -> SettingsScreen(vm)
                            else -> LogsScreen(vm)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Header(title: String, home: Boolean) {
    val cs = MaterialTheme.colorScheme
    Row(
        Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            Modifier.size(48.dp).clip(RoundedCornerShape(16.dp)).background(cs.primary),
            contentAlignment = Alignment.Center,
        ) {
            Text("光", color = cs.onPrimary, fontSize = 26.sp, fontWeight = FontWeight.Bold)
        }
        Text(
            if (home) stringResource(R.string.app_name) else title,
            style = MaterialTheme.typography.headlineMedium,
            color = cs.onSurface,
        )
    }
}

// ───────────────────────────── Home

@Composable
fun HomeScreen(vm: MainViewModel) {
    val running by vm.running.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
    val link = "tg://proxy?server=127.0.0.1&port=${settings.port}&secret=dd${settings.secret}"

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = Gutter, vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Hero(running, settings.port) { if (running) vm.stop() else vm.start() }

        error?.let {
            Surface(shape = MaterialTheme.shapes.large, color = cs.errorContainer, contentColor = cs.onErrorContainer) {
                Row(
                    Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(Icons.Rounded.ErrorOutline, null)
                    Text(it, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }

        Surface(shape = MaterialTheme.shapes.large, color = cs.surfaceContainer) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    IconBadge(Icons.AutoMirrored.Rounded.Send)
                    Text(stringResource(R.string.connect_title), style = MaterialTheme.typography.titleMedium)
                }
                Text(
                    stringResource(R.string.connect_desc),
                    style = MaterialTheme.typography.bodyMedium,
                    color = cs.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Button(
                        onClick = { openInTelegram(ctx, link) },
                        enabled = running,
                        modifier = Modifier.weight(1f).height(52.dp),
                    ) {
                        Text(stringResource(R.string.add_to_telegram), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    FilledTonalIconButton(
                        onClick = {
                            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            cm.setPrimaryClip(ClipData.newPlainText("proxy", link))
                            Toast.makeText(ctx, R.string.link_copied, Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.size(52.dp),
                    ) {
                        Icon(Icons.Rounded.ContentCopy, stringResource(R.string.copy_link))
                    }
                }
            }
        }

        Text(
            stringResource(R.string.stats_title),
            style = MaterialTheme.typography.titleMedium,
            color = cs.onSurfaceVariant,
            modifier = Modifier.padding(start = 8.dp, top = 6.dp),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TrafficTile(
                Icons.Rounded.ArrowUpward, stringResource(R.string.stat_up), Proto.humanBytes(stats.up),
                cs.primaryContainer, cs.onPrimaryContainer, Modifier.weight(1f),
            )
            TrafficTile(
                Icons.Rounded.ArrowDownward, stringResource(R.string.stat_down), Proto.humanBytes(stats.down),
                cs.tertiaryContainer, cs.onTertiaryContainer, Modifier.weight(1f),
            )
        }
        RoutesCard(stats.ws.toFloat(), stats.cf.toFloat(), stats.tcp.toFloat())
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            MiniTile(stringResource(R.string.stat_active), stats.active.toString(), Modifier.weight(1f))
            MiniTile(stringResource(R.string.stat_total), stats.total.toString(), Modifier.weight(1f))
            MiniTile(stringResource(R.string.stat_bad), stats.bad.toString(), Modifier.weight(1f))
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun Hero(running: Boolean, port: Int, onToggle: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val on by animateFloatAsState(if (running) 1f else 0f, tween(500), label = "heroOn")
    val fg by animateColorAsState(if (running) cs.onPrimary else cs.onSurface, tween(500), label = "heroFg")
    val btn by animateColorAsState(if (running) cs.onPrimary else cs.primary, tween(500), label = "heroBtn")
    val btnIcon by animateColorAsState(if (running) cs.primary else cs.onPrimary, tween(500), label = "heroBtnIcon")
    val buttonCenterY = 118.dp

    Box(
        Modifier
            .fillMaxWidth()
            .height(318.dp)
            .clip(MaterialTheme.shapes.extraLarge)
            .background(cs.surfaceContainerHigh),
    ) {
        Box(
            Modifier
                .fillMaxSize()
                .background(
                    Brush.linearGradient(listOf(cs.primary, lerp(cs.primary, cs.tertiary, 0.4f))),
                    alpha = on,
                ),
        )
        Text(
            "光",
            fontSize = 280.sp,
            fontWeight = FontWeight.Bold,
            color = fg.copy(alpha = 0.07f),
            modifier = Modifier.align(Alignment.BottomEnd).offset(x = 36.dp, y = 56.dp),
        )
        if (running) PulseRings(fg, buttonCenterY, Modifier.fillMaxSize())

        Column(
            Modifier.fillMaxSize().padding(top = 118.dp - 60.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Surface(
                onClick = onToggle,
                shape = CircleShape,
                color = btn,
                shadowElevation = 6.dp,
                modifier = Modifier.size(120.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.PowerSettingsNew, null, tint = btnIcon, modifier = Modifier.size(52.dp))
                }
            }
            Spacer(Modifier.height(22.dp))
            Text(
                stringResource(if (running) R.string.status_running else R.string.status_stopped),
                style = MaterialTheme.typography.titleLarge,
                color = fg,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(if (running) R.string.tap_to_stop else R.string.tap_to_start),
                style = MaterialTheme.typography.bodyMedium,
                color = fg.copy(alpha = 0.75f),
            )
            Spacer(Modifier.height(10.dp))
            Box(Modifier.clip(CircleShape).background(fg.copy(alpha = 0.12f)).padding(horizontal = 14.dp, vertical = 6.dp)) {
                Text("127.0.0.1:$port", style = MaterialTheme.typography.labelLarge, fontFamily = FontFamily.Monospace, color = fg)
            }
        }
    }
}

@Composable
private fun PulseRings(color: Color, centerY: Dp, modifier: Modifier) {
    val t = rememberInfiniteTransition(label = "pulse")
    val p by t.animateFloat(0f, 1f, infiniteRepeatable(tween(3000, easing = LinearEasing)), label = "p")
    Canvas(modifier) {
        for (k in 0..2) {
            val q = (p + k / 3f) % 1f
            drawCircle(
                color = color.copy(alpha = (1f - q) * 0.3f),
                radius = 62.dp.toPx() + q * 120.dp.toPx(),
                center = Offset(size.width / 2f, centerY.toPx()),
                style = Stroke(width = 2.dp.toPx()),
            )
        }
    }
}

@Composable
private fun IconBadge(icon: ImageVector) {
    val cs = MaterialTheme.colorScheme
    Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(14.dp)).background(cs.secondaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, null, tint = cs.onSecondaryContainer, modifier = Modifier.size(22.dp))
    }
}

@Composable
private fun TrafficTile(
    icon: ImageVector, label: String, value: String,
    container: Color, content: Color, modifier: Modifier = Modifier,
) {
    Surface(modifier = modifier, shape = MaterialTheme.shapes.large, color = container, contentColor = content) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(
                Modifier.size(34.dp).clip(CircleShape).background(content.copy(alpha = 0.12f)),
                contentAlignment = Alignment.Center,
            ) { Icon(icon, null, Modifier.size(20.dp)) }
            Column {
                Text(value, style = MaterialTheme.typography.headlineSmall, maxLines = 1)
                Text(label, style = MaterialTheme.typography.labelMedium, color = content.copy(alpha = 0.75f), maxLines = 1)
            }
        }
    }
}

@Composable
private fun RoutesCard(ws: Float, cf: Float, tcp: Float) {
    val cs = MaterialTheme.colorScheme
    val colors = listOf(cs.primary, cs.tertiary, cs.secondary)
    val values = listOf(ws, cf, tcp)
    val labels = listOf(R.string.stat_ws, R.string.stat_cf, R.string.stat_tcp)
    val sum = values.sum()
    Surface(shape = MaterialTheme.shapes.large, color = cs.surfaceContainer) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                IconBadge(Icons.Rounded.Router)
                Text(stringResource(R.string.routes_title), style = MaterialTheme.typography.titleMedium)
            }
            Row(Modifier.fillMaxWidth().height(12.dp).clip(CircleShape).background(cs.surfaceContainerHigh)) {
                if (sum > 0f) {
                    values.forEachIndexed { i, v ->
                        if (v > 0f) Box(Modifier.weight(v).fillMaxSize().background(colors[i]))
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                values.forEachIndexed { i, v ->
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Box(Modifier.size(8.dp).clip(CircleShape).background(colors[i]))
                        Column {
                            Text(v.toLong().toString(), style = MaterialTheme.typography.titleSmall)
                            Text(
                                stringResource(labels[i]),
                                style = MaterialTheme.typography.labelSmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MiniTile(label: String, value: String, modifier: Modifier = Modifier) {
    val cs = MaterialTheme.colorScheme
    Surface(modifier = modifier, shape = MaterialTheme.shapes.medium, color = cs.secondaryContainer) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, color = cs.onSecondaryContainer, maxLines = 1)
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = cs.onSecondaryContainer.copy(alpha = 0.72f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

private fun openInTelegram(ctx: Context, link: String) {
    try {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(ctx, R.string.telegram_missing, Toast.LENGTH_SHORT).show()
    }
}

// ───────────────────────────── Settings

@Composable
fun SettingsScreen(vm: MainViewModel) {
    val s by vm.settings.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val runningCfg by vm.runningConfig.collectAsStateWithLifecycle()
    val needsRestart = running && runningCfg != null && s.toConfig().getOrNull() != runningCfg
    val cs = MaterialTheme.colorScheme

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = Gutter, vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (needsRestart) {
            Surface(shape = MaterialTheme.shapes.large, color = cs.tertiaryContainer, contentColor = cs.onTertiaryContainer) {
                Row(
                    Modifier.padding(start = 20.dp, end = 12.dp, top = 12.dp, bottom = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(stringResource(R.string.restart_needed), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    FilledTonalButton(onClick = vm::restart) {
                        Icon(Icons.Rounded.RestartAlt, null, Modifier.size(18.dp))
                        Spacer(Modifier.size(6.dp))
                        Text(stringResource(R.string.restart))
                    }
                }
            }
        }

        SettingGroup(Icons.Rounded.Dns, stringResource(R.string.set_network)) {
            var portText by remember { mutableStateOf(s.port.toString()) }
            val portOk = portText.toIntOrNull()?.let { it in 1024..65535 } == true
            OutlinedTextField(
                value = portText,
                onValueChange = { v ->
                    portText = v.filter(Char::isDigit).take(5)
                    portText.toIntOrNull()?.takeIf { it in 1024..65535 }?.let { p -> vm.update { it.copy(port = p) } }
                },
                label = { Text(stringResource(R.string.set_port)) },
                isError = !portOk,
                supportingText = if (!portOk) ({ Text(stringResource(R.string.set_port_error)) }) else null,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = s.secret,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.set_secret)) },
                supportingText = { Text(stringResource(R.string.set_secret_note)) },
                leadingIcon = { Icon(Icons.Rounded.Key, null) },
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                trailingIcon = {
                    IconButton(onClick = vm::regenerateSecret) {
                        Icon(Icons.Rounded.Refresh, stringResource(R.string.set_regenerate))
                    }
                },
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        SettingGroup(Icons.Rounded.Speed, stringResource(R.string.set_routing)) {
            val dcOk = parseDcIps(s.dcIps).isSuccess
            OutlinedTextField(
                value = s.dcIps,
                onValueChange = { v -> vm.update { it.copy(dcIps = v) } },
                label = { Text(stringResource(R.string.set_dc)) },
                supportingText = { Text(stringResource(R.string.set_dc_hint)) },
                isError = !dcOk,
                minLines = 2,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth(),
            )
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.set_pool_title),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    Box(Modifier.clip(CircleShape).background(cs.primaryContainer).padding(horizontal = 12.dp, vertical = 4.dp)) {
                        Text(
                            if (s.poolSize == 0) stringResource(R.string.off) else s.poolSize.toString(),
                            style = MaterialTheme.typography.labelLarge,
                            color = cs.onPrimaryContainer,
                        )
                    }
                }
                Slider(
                    value = s.poolSize.toFloat(),
                    onValueChange = { v -> vm.update { it.copy(poolSize = v.toInt()) } },
                    valueRange = 0f..8f,
                    steps = 7,
                )
            }
        }

        SettingGroup(Icons.Rounded.Cloud, stringResource(R.string.set_cf)) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .clip(MaterialTheme.shapes.medium)
                    .clickable { vm.update { it.copy(cfFallback = !it.cfFallback) } },
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    stringResource(R.string.set_cf_desc),
                    style = MaterialTheme.typography.bodyMedium,
                    color = cs.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                Switch(checked = s.cfFallback, onCheckedChange = { c -> vm.update { it.copy(cfFallback = c) } })
            }
            OutlinedTextField(
                value = s.cfDomains,
                onValueChange = { v -> vm.update { it.copy(cfDomains = v) } },
                enabled = s.cfFallback,
                label = { Text(stringResource(R.string.set_cf_domains)) },
                supportingText = { Text(stringResource(R.string.set_cf_domains_hint)) },
                minLines = 2,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun SettingGroup(icon: ImageVector, title: String, content: @Composable () -> Unit) {
    Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                IconBadge(icon)
                Text(title, style = MaterialTheme.typography.titleMedium)
            }
            content()
        }
    }
}

// ───────────────────────────── Logs

@Composable
fun LogsScreen(vm: MainViewModel) {
    val logs by vm.logs.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
    val state = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) state.scrollToItem(logs.lastIndex)
    }
    Column(Modifier.fillMaxSize().padding(horizontal = Gutter)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${logs.size}",
                style = MaterialTheme.typography.labelLarge,
                color = cs.onSurfaceVariant,
                modifier = Modifier.weight(1f).padding(start = 8.dp),
            )
            FilledTonalIconButton(onClick = {
                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("logs", logs.joinToString("\n")))
            }, enabled = logs.isNotEmpty()) {
                Icon(Icons.Rounded.ContentCopy, stringResource(R.string.logs_copy), Modifier.size(20.dp))
            }
            Spacer(Modifier.size(8.dp))
            FilledTonalIconButton(onClick = vm::clearLogs, enabled = logs.isNotEmpty()) {
                Icon(Icons.Rounded.DeleteSweep, stringResource(R.string.logs_clear), Modifier.size(20.dp))
            }
        }
        Spacer(Modifier.height(8.dp))
        if (logs.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("光", fontSize = 72.sp, fontWeight = FontWeight.Bold, color = cs.primary.copy(alpha = 0.25f))
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.logs_empty),
                        color = cs.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        } else {
            Surface(
                modifier = Modifier.fillMaxSize().padding(bottom = 12.dp),
                shape = MaterialTheme.shapes.large,
                color = cs.surfaceContainer,
            ) {
                LazyColumn(state = state, modifier = Modifier.fillMaxSize().padding(14.dp)) {
                    items(logs.size) { i ->
                        val line = logs[i]
                        Text(
                            line,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 16.sp,
                            color = if (line.length > 9 && line[9] == 'W') cs.error else cs.onSurface,
                        )
                    }
                }
            }
        }
    }
}
