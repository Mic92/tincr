package io.thalheim.tincr

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

// Daily hosts/ refresh, also kicked on VPN start and app open.
class BundleJob : JobService() {
    companion object {
        private const val ID = 1
        private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "tincr-bundle").apply { isDaemon = true } }

        @Volatile
        var lastProblem: Problem? = null
            private set

        fun schedule(context: Context) {
            val js = context.getSystemService(JobScheduler::class.java) ?: return
            if (js.getPendingJob(ID) != null) return
            js.schedule(
                JobInfo.Builder(ID, ComponentName(context, BundleJob::class.java))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(TimeUnit.DAYS.toMillis(1))
                    .setPersisted(true)
                    .build(),
            )
        }

        // Serialised on one thread so two refreshes never race on hosts.new/.
        fun kick(context: Context, config: NetworkConfig, done: () -> Unit = {}) {
            val url = config.bundleUrl ?: return done()
            executor.execute {
                try {
                    if (Bundle.update(config) && Vpn.running) TincCtl(config.dir).request(TincCtl.REQ_RELOAD)
                    lastProblem = null
                } catch (e: Exception) {
                    Log.w("tincr", "bundle: ${e.message}")
                    lastProblem = Problems.bundle(url, e)
                } finally {
                    done()
                }
            }
        }
    }

    override fun onStartJob(params: JobParameters): Boolean {
        val config = NetworkConfig.load(File(filesDir, "networks/default"))
        if (config.bundleUrl == null) return false
        kick(this, config) { jobFinished(params, false) }
        return true
    }

    override fun onStopJob(params: JobParameters) = false
}
