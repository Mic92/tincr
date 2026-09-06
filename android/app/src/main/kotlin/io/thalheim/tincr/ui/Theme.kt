package io.thalheim.tincr.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

object Palette {
    val green = Color(0xFF16A34A)
    val greenSoft = Color(0xFFDCFCE7)
    val grey = Color(0xFF6B7280)
    val greySoft = Color(0xFFF3F4F6)
    val amberInk = Color(0xFF92400E)
    val amberSoft = Color(0xFFFEF3C7)
    val blue = Color(0xFF2563EB)
    val blueSoft = Color(0xFFDBEAFE)
    val line = Color(0xFFE5E7EB)
    val bg = Color(0xFFF4F5F7)
}

@Composable
fun TincrTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = lightColorScheme(primary = Palette.blue, background = Palette.bg),
        content = content,
    )
}
