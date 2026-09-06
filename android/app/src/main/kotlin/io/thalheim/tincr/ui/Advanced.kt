package io.thalheim.tincr.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun AdvancedScreen(log: String, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Palette.bg).statusBarsPadding().padding(horizontal = 20.dp)) {
        Row(Modifier.padding(top = 18.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack, "Back",
                modifier = Modifier.size(28.dp).clickable(role = Role.Button, onClick = onBack),
            )
            Spacer(Modifier.width(12.dp))
            Text("Advanced", fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(16.dp))
        Text("Daemon log", fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text(
            log, fontFamily = FontFamily.Monospace, fontSize = 10.sp, lineHeight = 13.sp,
            modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
        )
    }
}
