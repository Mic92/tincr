package io.thalheim.tincr

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

class MainActivity : Activity() {
    private lateinit var logView: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val refreshLog = object : Runnable {
        override fun run() {
            val f = File(filesDir, "networks/default/tincd.log")
            logView.text = if (f.isFile) {
                f.readLines().takeLast(100).joinToString("\n")
            } else {
                "(no log)"
            }
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        layout.addView(Button(this).apply {
            text = "Start VPN"
            setOnClickListener { prepareAndStart() }
        })
        layout.addView(Button(this).apply {
            text = "Stop VPN"
            setOnClickListener {
                startService(
                    Intent(this@MainActivity, TincrVpnService::class.java)
                        .setAction(TincrVpnService.ACTION_STOP)
                )
            }
        })
        logView = TextView(this).apply { textSize = 10f }
        layout.addView(ScrollView(this).apply { addView(logView) })
        setContentView(layout)
        // adb/test entry. Consent must be pre-granted via appops.
        if (intent.getBooleanExtra("autostart", false)) {
            prepareAndStart()
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refreshLog)
    }

    override fun onPause() {
        handler.removeCallbacks(refreshLog)
        super.onPause()
    }

    private fun prepareAndStart() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, 0)
        } else {
            onActivityResult(0, RESULT_OK, null)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            startForegroundService(Intent(this, TincrVpnService::class.java))
        }
    }
}
