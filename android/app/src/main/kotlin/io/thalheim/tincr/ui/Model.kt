package io.thalheim.tincr.ui

import io.thalheim.tincr.Problem

enum class Link { Connected, Connecting, Off }

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
    val notice: Problem? = null,
) {
    val onlineCount get() = devices.count { it.online }
}
