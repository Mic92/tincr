package io.thalheim.tincr

import java.io.File

// Every failure the app can detect maps to one of these so people either
// fix it themselves or forward something an operator can act on.
object Problems {
    fun notJoined() = Problem(
        "Not set up yet",
        "Open the invitation link or scan the code you were given.",
    )

    fun consentMissing() = Problem(
        "VPN permission needed",
        "Android asks once whether tincr may create a VPN. Tap Connect and allow it. " +
            "If another VPN app is set to always-on, turn that off in Android settings first.",
    )

    fun revoked() = Problem(
        "Another VPN took over",
        "Android allows one VPN at a time. Tap Connect to switch back to tincr.",
    )

    fun establishFailed(e: Throwable?) = Problem(
        "Android refused the VPN interface",
        "Restart the phone. If it keeps happening send a help report.",
        "VpnService.establish(): ${e?.let { "${it.javaClass.simpleName}: ${it.message}" } ?: "returned null 5x"}",
    )

    fun badConfig(what: String) = Problem(
        "The saved network settings are damaged",
        "Ask for a new invitation and join again. Your old entry will be replaced.",
        what,
    )

    fun binaryMissing(f: File) = Problem(
        "This install is incomplete",
        "Reinstall tincr from where you got it. The VPN engine is missing from the app package.",
        "not executable: $f",
    )

    fun crashed(rc: Int, logTail: String, restartingInMs: Long) = Problem(
        "Connection engine stopped, retrying",
        "tincr restarts it by itself. If this stays for minutes, send a help report.",
        "tincd exit $rc, restart in ${restartingInMs / 1000}s\n$logTail",
    )

    fun crashLoop(rc: Int, logTail: String) = Problem(
        "Can’t keep the connection engine running",
        "Send a help report so the person who invited you can see why.",
        "tincd exit $rc repeatedly\n$logTail",
    )

    fun noInternet() = Problem(
        "No internet connection",
        "The network will reconnect by itself when you’re back online.",
    )

    fun peerUnreachable(inviter: String, seconds: Long, logTail: String) = Problem(
        "Can’t reach $inviter",
        "Your internet works but $inviter’s server does not answer. It may be down, " +
            "or this Wi-Fi blocks VPNs. Try mobile data. If that does not help, tell $inviter.",
        "no meta connection after ${seconds}s\n$logTail",
    )

    fun bundle(url: String, e: Throwable) = Problem(
        "Device list could not be updated",
        "Connecting still works with the list from last time. tincr retries daily and whenever you open the app.",
        "GET $url: ${e.javaClass.simpleName}: ${e.message}",
    )

    fun newPhone(inviter: String) = Problem(
        "This looks like a new phone",
        "Keys do not move between phones. Ask $inviter for a fresh invitation.",
    )
}
