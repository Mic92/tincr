package io.thalheim.tincr

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
    private var netCallback: ConnectivityManager.NetworkCallback? = null

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
        if (daemon != null) return
        val config = NetworkConfig.load(File(filesDir, "networks/default"))
        val tun = establishWithRetry(config) ?: run {
            Log.e(TAG, "establish() returned null (VPN permission revoked?)")
            stopSelf()
            return
        }
        this.tun = tun

        val fdServer = TunFdServer(TUN_SOCKET, tun.fileDescriptor)
        daemon = TincdRunner(this, config).also { it.start() }
        // tincd connects to @tincr-tun and receives the tun fd.
        fdServer.serveOnce()
        watchNetwork(config)
    }

    // Retry: consent may land just after service start.
    private fun establishWithRetry(config: NetworkConfig): ParcelFileDescriptor? {
        repeat(5) { attempt ->
            Builder()
                .setSession("tincr")
                .setMtu(config.mtu)
                .apply {
                    config.addresses.forEach { addAddress(it.address, it.prefix) }
                    config.routes.forEach { addRoute(it.address, it.prefix) }
                    config.dnsServers.forEach { addDnsServer(it) }
                    config.searchDomains.forEach { addSearchDomain(it) }
                }
                .establish()?.let { return it }
            Log.w(TAG, "establish() null, attempt $attempt")
            Thread.sleep(1000)
        }
        return null
    }

    // On network change tell tincd to redial past its backoff.
    private fun watchNetwork(config: NetworkConfig) {
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                thread(name = "tincr-retry") {
                    TincCtl(config.dir).request(TincCtl.REQ_RETRY)
                }
            }
        }
        cm.registerNetworkCallback(
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build(),
            cb,
        )
        netCallback = cb
    }

    private fun stopVpn() {
        netCallback?.let {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
        }
        netCallback = null
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
