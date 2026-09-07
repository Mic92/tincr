package io.thalheim.tincr.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class Tab(val label: String, val icon: ImageVector) {
    Home("Home", Icons.Filled.PowerSettingsNew),
    Devices("Devices", Icons.Filled.Group),
    Help("Help", Icons.AutoMirrored.Filled.HelpOutline),
}

@Composable
fun OnboardingScreen(onScan: () -> Unit, onLink: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(Palette.bg).statusBarsPadding().padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(96.dp))
        Box(
            Modifier.size(88.dp).clip(RoundedCornerShape(24.dp)).background(Palette.blue),
            contentAlignment = Alignment.Center,
        ) { Text("t", color = Color.White, fontSize = 40.sp, fontWeight = FontWeight.Bold) }
        Spacer(Modifier.height(20.dp))
        Text("Welcome to tincr", fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Muted("Someone in your family or team\ncan invite you to their network.")
        Spacer(Modifier.height(44.dp))
        BigButton("Scan invitation code", Icons.Filled.QrCodeScanner, primary = true, onScan)
        Spacer(Modifier.height(14.dp))
        BigButton("I got an invitation link", Icons.Filled.Link, primary = false, onLink)
        Spacer(Modifier.weight(1f))
        Muted("No account. No sign-up.\nThe invitation is all you need.")
        Spacer(Modifier.height(28.dp))
    }
}

// Paste-a-link step of onboarding. `busy` while the exchange runs,
// `error` is shown verbatim under the field.
@Composable
fun JoinScreen(
    link: String,
    onLink: (String) -> Unit,
    busy: Boolean,
    error: String?,
    onJoin: () -> Unit,
    onBack: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().background(Palette.bg).statusBarsPadding().padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(96.dp))
        Text("Paste your invitation", fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Muted("It looks like tinc://join/… and works once.")
        Spacer(Modifier.height(28.dp))
        OutlinedTextField(
            link, onLink, Modifier.fillMaxWidth(), enabled = !busy, singleLine = true,
            label = { Text("Invitation link") }, isError = error != null,
            supportingText = { if (error != null) Text(error, color = Palette.amberInk) },
        )
        Spacer(Modifier.height(20.dp))
        if (busy) {
            CircularProgressIndicator(color = Palette.blue)
            Spacer(Modifier.height(12.dp))
            Muted("Joining…")
        } else {
            BigButton("Join network", Icons.Filled.Link, primary = true, onJoin)
            Spacer(Modifier.height(14.dp))
            BigButton("Back", Icons.AutoMirrored.Filled.ArrowBack, primary = false, onBack)
        }
    }
}

@Composable
fun MainScreen(
    state: HomeState,
    tab: Tab,
    onTab: (Tab) -> Unit,
    onToggle: () -> Unit,
    onHelpReport: () -> Unit,
    onSettings: () -> Unit,
) {
    Scaffold(
        containerColor = Palette.bg,
        bottomBar = {
            NavigationBar(containerColor = Color.White) {
                Tab.entries.forEach {
                    NavigationBarItem(
                        selected = it == tab,
                        onClick = { onTab(it) },
                        icon = { Icon(it.icon, null) },
                        label = { Text(it.label) },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = Palette.blueSoft,
                            selectedIconColor = Palette.blue,
                            selectedTextColor = Palette.blue,
                        ),
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).padding(horizontal = 20.dp).fillMaxSize()) {
            when (tab) {
                Tab.Home -> HomeTab(state, onToggle, { onTab(Tab.Devices) }, onSettings)
                Tab.Devices -> DevicesTab(state, onHelpReport)
                Tab.Help -> HelpTab(state, onHelpReport)
            }
        }
    }
}

@Composable
private fun HomeTab(state: HomeState, onToggle: () -> Unit, onDevices: () -> Unit, onSettings: () -> Unit) {
    val (ring, soft, word) = when (state.link) {
        Link.Connected -> Triple(Palette.green, Palette.greenSoft, "CONNECTED")
        Link.Connecting -> Triple(Palette.blue, Palette.blueSoft, "CONNECTING")
        Link.Off -> Triple(Palette.grey, Palette.greySoft, "OFF")
    }
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(
            Modifier.fillMaxWidth().padding(top = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(state.network, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Icon(
                Icons.Filled.Settings, "Settings", tint = Palette.grey,
                modifier = Modifier.size(28.dp).clickable(role = Role.Button, onClick = onSettings),
            )
        }
        state.notice?.let { NoticeBanner(it) }
        Spacer(Modifier.height(40.dp))
        Box(
            Modifier.size(190.dp).clip(CircleShape).background(soft)
                .border(10.dp, ring, CircleShape)
                .clickable(role = Role.Switch, onClick = onToggle)
                .semantics { contentDescription = "VPN ${word.lowercase()}, tap to toggle" },
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Filled.PowerSettingsNew, null, tint = ring, modifier = Modifier.size(56.dp))
                Text(word, color = ring, fontSize = 15.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            }
        }
        Spacer(Modifier.height(30.dp))
        val (headline, detail) = when (state.link) {
            Link.Connected -> "You’re connected" to
                "Your family’s devices can be reached.\nEverything else works as usual."
            Link.Connecting -> "Connecting…" to "This usually takes a few seconds."
            Link.Off -> "Not connected" to "Tap the button to connect."
        }
        Text(headline, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Muted(detail)
        Spacer(Modifier.weight(1f))
        Card(Modifier.clickable(onClick = onDevices)) {
            val live = state.link == Link.Connected
            Dot(if (live && state.onlineCount > 0) Palette.green else Palette.grey)
            Spacer(Modifier.width(12.dp))
            Text(
                if (live) "${state.onlineCount} of ${state.devices.size} devices online"
                else "${state.devices.size} devices",
                fontSize = 15.sp, modifier = Modifier.weight(1f),
            )
            Text("›", color = Palette.grey, fontSize = 18.sp)
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun DevicesTab(state: HomeState, onHelpReport: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Text("Devices", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 18.dp))
        state.notice?.let { NoticeBanner(it) }
        Spacer(Modifier.height(20.dp))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            state.devices.forEach { DeviceRow(it) }
        }
        Spacer(Modifier.weight(1f))
        HelpButton(state.inviter, onHelpReport)
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun HelpTab(state: HomeState, onHelpReport: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Text("Help", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 18.dp))
        Spacer(Modifier.height(16.dp))
        Muted(
            "If something doesn’t work, send a help report. It contains the " +
                "app’s log so ${state.inviter} can see what went wrong.",
            align = TextAlign.Start,
        )
        Spacer(Modifier.height(20.dp))
        HelpButton(state.inviter, onHelpReport)
    }
}

@Composable
private fun DeviceRow(d: Device) {
    val palette = listOf(Palette.blue, Palette.green, Color(0xFFD97706), Color(0xFF7C3AED))
    Card {
        Box(
            Modifier.size(44.dp).clip(CircleShape)
                .background(palette[(d.name.hashCode() and 0xffff) % palette.size]),
            contentAlignment = Alignment.Center,
        ) { Text(d.name.take(1), color = Color.White, fontWeight = FontWeight.Bold, fontSize = 17.sp) }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(d.name, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Text(if (d.self) "This device" else d.role, fontSize = 13.sp, color = Palette.grey)
        }
        Pill(d.online)
    }
}

@Composable
private fun NoticeBanner(n: Notice) {
    Column(
        Modifier.padding(top = 16.dp).fillMaxWidth()
            .clip(RoundedCornerShape(14.dp)).background(Palette.amberSoft).padding(14.dp),
    ) {
        Text(n.title, color = Palette.amberInk, fontSize = 15.sp, fontWeight = FontWeight.Bold)
        Text(n.body, color = Palette.amberInk.copy(alpha = .85f), fontSize = 14.sp)
    }
}

@Composable
private fun HelpButton(inviter: String, onClick: () -> Unit) {
    Button(
        onClick, Modifier.fillMaxWidth().height(56.dp), shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Palette.blueSoft, contentColor = Palette.blue),
    ) { Text("Send help report to $inviter", fontSize = 16.sp, fontWeight = FontWeight.SemiBold) }
}

@Composable
private fun BigButton(label: String, icon: ImageVector, primary: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    val mod = Modifier.fillMaxWidth().height(64.dp)
    val content: @Composable () -> Unit = {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, modifier = Modifier.size(26.dp))
            Spacer(Modifier.width(14.dp))
            Text(label, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
        }
    }
    if (primary) {
        Button(onClick, mod, shape = shape) { content() }
    } else {
        OutlinedButton(
            onClick, mod, shape = shape, border = BorderStroke(1.dp, Palette.line),
            colors = ButtonDefaults.outlinedButtonColors(containerColor = Color.White, contentColor = Color.Black),
        ) { content() }
    }
}

@Composable
private fun Card(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    Surface(
        modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
        color = Color.White, border = BorderStroke(1.dp, Palette.line),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { content() }
    }
}

@Composable
private fun Pill(online: Boolean) {
    Text(
        if (online) "online" else "offline",
        color = if (online) Palette.green else Palette.grey,
        fontSize = 12.sp, fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(50))
            .background(if (online) Palette.greenSoft else Palette.greySoft)
            .padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

@Composable
private fun Dot(color: Color) {
    Box(Modifier.size(10.dp).clip(CircleShape).background(color))
}

@Composable
private fun Muted(text: String, align: TextAlign = TextAlign.Center) {
    Text(text, color = Palette.grey, fontSize = 15.sp, lineHeight = 22.sp, textAlign = align)
}
