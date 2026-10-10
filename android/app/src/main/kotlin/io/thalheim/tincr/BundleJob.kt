package io.thalheim.tincr

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

// Daily hosts/ refresh. Also run on every VPN start.
class BundleJob : JobService() {
    companion object {
        private const val ID = 1

        fun schedule(context: Context) {
            val js = context.getSystemService(JobScheduler::class.java)
            if (js.getPendingJob(ID) != null) return
            js.schedule(
                JobInfo.Builder(ID, ComponentName(context, BundleJob::class.java))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(TimeUnit.DAYS.toMillis(1))
                    .setPersisted(true)
                    .build(),
            )
        }

        @Synchronized
        fun refresh(config: NetworkConfig) {
            try {
                if (Bundle.update(config) && TincrVpnService.running) {
                    TincCtl(config.dir).request(TincCtl.REQ_RELOAD)
                }
            } catch (e: Exception) {
                Log.w("tincr", "bundle update failed: ${e.message}")
            }
        }
    }

    override fun onStartJob(params: JobParameters): Boolean {
        val config = NetworkConfig.load(File(filesDir, "networks/default"))
        if (config.bundleUrl == null) return false
        thread(name = "tincr-bundle") {
            refresh(config)
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters) = false
}
