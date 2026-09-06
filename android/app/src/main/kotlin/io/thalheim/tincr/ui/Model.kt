package io.thalheim.tincr.ui

enum class Link { Connected, Connecting, Off }

// Degraded states are phrased as instructions, never diagnoses.
enum class Notice(val title: String, val body: String) {
    NoInternet(
        "No internet connection",
        "The network will reconnect by itself when you’re back online.",
    ),
    NewPhone(
        "This looks like a new phone",
        "Ask the person who invited you for a fresh invitation.",
    ),
}

data class Device(
    val name: String,
    val role: String,
    val online: Boolean,
    val self: Boolean = false,
)

data class HomeState(
    val network: String,
    val link: Link,
    val devices: List<Device>,
    val inviter: String,
    val notice: Notice? = null,
) {
    val onlineCount get() = devices.count { it.online }
}
