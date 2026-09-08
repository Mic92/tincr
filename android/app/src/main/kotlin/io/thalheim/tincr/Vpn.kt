package io.thalheim.tincr

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

enum class Phase { Off, Starting, Running, Stopping }

// What the user sees when something is wrong: an instruction first, the
// technical detail below it for passing on.
data class Problem(val title: String, val body: String, val detail: String = "")

// Single source of truth for the UI. Written by the service thread only.
object Vpn {
    var phase by mutableStateOf(Phase.Off)
        internal set
    var problem by mutableStateOf<Problem?>(null)
        internal set

    val running get() = phase == Phase.Running
}
