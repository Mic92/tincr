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
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

// All state lives on one HandlerThread. Binder callbacks, tincd exit and
// network events only post to it, so there is no locking and no ordering
// surprises between start, stop, crash and revoke.
class TincrVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "io.thalheim.tincr.STOP"
        const val WANTED = "vpn.wanted"
        private const val TAG = "tincr"
        private const val CHANNEL = "tincr-vpn"
        private const val TUN_SOCKET = "tincr-tun"
        private const val STABLE_MS = 60_000L
        private const val MAX_CRASHES = 8
        private const val PEER_GRACE_MS = 20_000L
    }

    private class Session(
        val config: NetworkConfig,
        val tun: ParcelFileDescriptor,
        val fdServer: TunFdServer,
        var daemon: TincdRunner? = null,
        var crashes: Int = 0,
        var since: Long = 0,
    )

    private lateinit var thread: HandlerThread
    private lateinit var handler: Handler
    private val peerCheck = Runnable { checkPeer() }
    private var session: Session? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private val netDir by lazy { File(filesDir, "networks/default") }
    private val binary by lazy { File(applicationInfo.nativeLibraryDir, "libtincd.so") }

    override fun onCreate() {
        super.onCreate()
        thread = HandlerThread("tincr-vpn").apply { start() }
        handler = Handler(thread.looper)
    }

    // Null intent: START_STICKY restart or always-on VPN.
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            wanted(false)
            handler.post { down(); stopSelf() }
            return START_NOT_STICKY
        }
        startForeground(1, notification())
        wanted(true)
        handler.post { up() }
        return START_STICKY
    }

    override fun onRevoke() {
        wanted(false)
        handler.post {
            down()
            Vpn.problem = Problems.revoked()
            stopSelf()
        }
    }

    override fun onDestroy() {
        handler.post { down() }
        thread.quitSafely()
        thread.join(10_000)
        super.onDestroy()
    }

    private fun wanted(on: Boolean) {
        val f = File(netDir, WANTED)
        runCatching { if (on) { f.parentFile?.mkdirs(); f.writeText("") } else f.delete() }
    }

    private fun fail(p: Problem) {
        Log.e(TAG, "${p.title}: ${p.detail}")
        Vpn.problem = p
        down()
        wanted(false)
        stopSelf()
    }

    private fun up() {
        if (session != null) return
        Vpn.phase = Phase.Starting
        Vpn.problem = null
        if (!File(netDir, "tinc.conf").isFile) return fail(Problems.notJoined())
        if (!binary.canExecute()) return fail(Problems.binaryMissing(binary))
        val config = NetworkConfig.load(netDir)
        if (config.addresses.isEmpty()) return fail(Problems.badConfig("vpn.conf has no address line"))
        if (config.name == null) return fail(Problems.badConfig("tinc.conf has no Name"))
        if (!File(netDir, "ed25519_key.priv").isFile) return fail(Problems.newPhone(config.inviter ?: "the person who invited you"))
        val tun = establish(config) ?: return
        val fdServer = try {
            TunFdServer(TUN_SOCKET, tun.fileDescriptor)
        } catch (e: java.io.IOException) {
            runCatching { tun.close() }
            return fail(Problems.establishFailed(e))
        }
        session = Session(config, tun, fdServer)
        spawn()
        watchNetwork()
        Vpn.phase = Phase.Running
        armPeerCheck()
        BundleJob.kick(this, config)
        BundleJob.schedule(this)
    }

    private fun establish(config: NetworkConfig): ParcelFileDescriptor? {
        var last: Throwable? = null
        repeat(5) { attempt ->
            try {
                Builder()
                    .setSession(config.network ?: "tincr")
                    .setMtu(config.mtu)
                    .apply {
                        config.addresses.forEach { addAddress(it.address, it.prefix) }
                        config.routes.forEach { addRoute(it.address, it.prefix) }
                        config.dnsServers.forEach { addDnsServer(it) }
                        config.searchDomains.forEach { addSearchDomain(it) }
                    }
                    .establish()?.let { return it }
                // null: consent not (yet) granted.
                if (prepare(this) != null) {
                    fail(Problems.consentMissing())
                    return null
                }
            } catch (e: IllegalArgumentException) {
                fail(Problems.badConfig("VpnService.Builder: ${e.message}"))
                return null
            } catch (e: RuntimeException) {
                last = e
            }
            Log.w(TAG, "establish() failed, attempt $attempt")
            Thread.sleep(1000)
        }
        fail(Problems.establishFailed(last))
        return null
    }

    private fun spawn() {
        val s = session ?: return
        val runner = TincdRunner(binary, s.config.dir)
        s.daemon = runner
        s.since = System.currentTimeMillis()
        try {
            runner.start { rc -> handler.post { exited(runner, rc) } }
        } catch (e: java.io.IOException) {
            fail(Problems.binaryMissing(binary).copy(detail = "exec: ${e.message}"))
        }
    }

    private fun exited(runner: TincdRunner, rc: Int) {
        val s = session?.takeIf { it.daemon === runner } ?: return
        s.daemon = null
        val tail = TincdRunner.logTail(s.config.dir)
        if (System.currentTimeMillis() - s.since > STABLE_MS) s.crashes = 0
        if (++s.crashes > MAX_CRASHES) return fail(Problems.crashLoop(rc, tail))
        val wait = 1000L shl minOf(s.crashes - 1, 5)
        Log.w(TAG, "tincd exited with $rc, restart in ${wait}ms")
        Vpn.problem = Problems.crashed(rc, tail, wait)
        handler.postDelayed({
            if (session === s && s.daemon == null) {
                spawn()
                armPeerCheck()
            }
        }, wait)
    }

    // After a grace period with internet but no meta connection, say so.
    private fun checkPeer() {
        val s = session ?: return
        val conns = TincCtl(s.config.dir).metaConnections() ?: return
        val online = getSystemService(ConnectivityManager::class.java).let { cm ->
            cm.getNetworkCapabilities(cm.activeNetwork)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        }
        Vpn.problem = when {
            conns > 0 -> null
            !online -> Problems.noInternet()
            else -> Problems.peerUnreachable(
                s.config.inviter ?: "the server", (System.currentTimeMillis() - s.since) / 1000,
                TincdRunner.logTail(s.config.dir),
            )
        }
        if (conns == 0) armPeerCheck()
    }

    private fun armPeerCheck() {
        handler.removeCallbacks(peerCheck)
        handler.postDelayed(peerCheck, PEER_GRACE_MS)
    }

    private fun watchNetwork() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handler.post {
                    val s = session ?: return@post
                    TincCtl(s.config.dir).request(TincCtl.REQ_RETRY)
                    armPeerCheck()
                }
            }

            override fun onLost(network: Network) {
                handler.post { if (session != null) checkPeer() }
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

    private fun down() {
        val s = session ?: run { Vpn.phase = Phase.Off; return }
        Vpn.phase = Phase.Stopping
        session = null
        handler.removeCallbacksAndMessages(null)
        netCallback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }
        netCallback = null
        s.daemon?.let { runCatching { it.stop() }.onFailure { e -> Log.w(TAG, "stop: ${e.message}") } }
        s.daemon = null
        s.fdServer.close()
        runCatching { s.tun.close() }
        Vpn.phase = Phase.Off
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("tincr")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
    }
}
