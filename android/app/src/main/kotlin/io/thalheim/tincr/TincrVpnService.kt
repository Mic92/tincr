package io.thalheim.tincr

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlin.concurrent.thread

class TincrVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "io.thalheim.tincr.STOP"
        private const val TAG = "tincr"
        private const val CHANNEL = "tincr-vpn"
        private const val TUN_SOCKET = "tincr-tun"
    }

    private var tun: ParcelFileDescriptor? = null
    private var daemon: TincdRunner? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(1, notification())
        thread(name = "tincr-start") { startVpn() }
        return START_STICKY
    }

    private fun startVpn() {
        val config = NetworkConfig.load(File(filesDir, "networks/default"))
        val tun = Builder()
            .setSession("tincr")
            .setMtu(config.mtu)
            .apply {
                config.addresses.forEach { addAddress(it.address, it.prefix) }
                config.routes.forEach { addRoute(it.address, it.prefix) }
                config.dnsServers.forEach { addDnsServer(it) }
                config.searchDomains.forEach { addSearchDomain(it) }
            }
            .establish() ?: run {
                Log.e(TAG, "establish() returned null (VPN permission revoked?)")
                stopSelf()
                return
            }
        this.tun = tun

        val fdServer = TunFdServer(TUN_SOCKET, tun.fileDescriptor)
        daemon = TincdRunner(this, config).also { it.start() }
        // tincd connects to @tincr-tun and receives the tun fd.
        fdServer.serveOnce()
    }

    private fun stopVpn() {
        daemon?.stop()
        daemon = null
        tun?.close()
        tun = null
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW)
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("tincr")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
    }
}
