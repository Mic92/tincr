package io.thalheim.tincr

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import java.io.File

// Restores the VPN after boot/update if it was on and consent still holds.
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val wanted = File(context.filesDir, "networks/default/${TincrVpnService.WANTED}")
        if (!wanted.isFile || VpnService.prepare(context) != null) return
        context.startForegroundService(Intent(context, TincrVpnService::class.java))
    }
}
