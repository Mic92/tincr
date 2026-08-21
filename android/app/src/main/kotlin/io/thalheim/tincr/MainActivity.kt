package io.thalheim.tincr

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout

class MainActivity : Activity() {
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
        setContentView(layout)
        // adb testing: am start ... --ez autostart true (consent
        // must already be granted, e.g. via appops ACTIVATE_VPN).
        if (intent.getBooleanExtra("autostart", false)) {
            prepareAndStart()
        }
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
