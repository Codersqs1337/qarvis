package com.qasim.qarvis

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private lateinit var status: TextView
    private lateinit var keyField: EditText

    private val amber = Color.parseColor("#FFB000")
    private val ash = Color.parseColor("#5C6672")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setBackgroundColor(Color.parseColor("#05070A"))
        root.setPadding(48, 72, 48, 48)

        val title = TextView(this)
        title.text = "QARVIS"
        title.setTextColor(amber)
        title.textSize = 34f
        title.letterSpacing = 0.25f
        root.addView(title)
        root.addView(label("Offline voice assistant - v0.2"))

        root.addView(label("\n1. Picovoice AccessKey"))
        root.addView(label("Free at console.picovoice.ai. Paste it here once."))
        keyField = EditText(this)
        keyField.setTextColor(Color.WHITE)
        keyField.setHintTextColor(ash)
        keyField.hint = "paste AccessKey"
        keyField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        keyField.setText(Prefs.accessKey(this))
        root.addView(keyField)
        root.addView(button("SAVE KEY") {
            Prefs.setAccessKey(this, keyField.text.toString())
            toast("Key saved")
            refresh()
        })

        root.addView(label("\n2. Permissions"))
        root.addView(button("MICROPHONE + CALLS") {
            val base = arrayOf(
                Manifest.permission.RECORD_AUDIO,
                Manifest.permission.CALL_PHONE,
                Manifest.permission.ANSWER_PHONE_CALLS,
                Manifest.permission.READ_PHONE_STATE
            )
            val all = if (Build.VERSION.SDK_INT >= 33)
                base + arrayOf(Manifest.permission.POST_NOTIFICATIONS) else base
            requestPermissions(all, 1)
        })
        root.addView(button("DRAW OVER OTHER APPS") {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        })
        root.addView(button("IGNORE BATTERY OPTIMISATION") {
            try {
                startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
            } catch (e: Exception) {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            }
        })

        root.addView(label("\n3. Run"))
        root.addView(button("START QARVIS") {
            if (Prefs.accessKey(this).isBlank()) {
                toast("Save an AccessKey first")
            } else {
                startForegroundService(Intent(this, QarvisService::class.java))
                toast("Listening. Say the wake word.")
                postRefresh()
            }
        })
        root.addView(button("STOP QARVIS") {
            stopService(Intent(this, QarvisService::class.java))
            postRefresh()
        })

        status = TextView(this)
        status.setTextColor(ash)
        status.textSize = 13f
        status.setPadding(0, 40, 0, 0)
        root.addView(status)

        root.addView(label("\nWake word is JARVIS until you add a custom qarvis.ppn model. Everything runs on-device: no audio ever leaves the phone."))

        val scroll = ScrollView(this)
        scroll.setBackgroundColor(Color.parseColor("#05070A"))
        scroll.addView(root)
        setContentView(scroll)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun refresh() {
        val overlay = Settings.canDrawOverlays(this)
        val mic = checkSelfPermission(Manifest.permission.RECORD_AUDIO) == 0
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        val unrestricted = pm.isIgnoringBatteryOptimizations(packageName)
        val key = Prefs.accessKey(this).isNotBlank()

        status.text = mark(key) + " AccessKey\n" +
                mark(mic) + " Microphone\n" +
                mark(overlay) + " Overlay\n" +
                mark(unrestricted) + " Battery unrestricted\n" +
                mark(QarvisService.isRunning) + " Service running\n\n" +
                QarvisService.status
    }

    private fun postRefresh() { status.postDelayed({ refresh() }, 900) }

    private fun mark(ok: Boolean) = if (ok) "[ OK ]" else "[    ]"

    private fun label(text: String): TextView {
        val t = TextView(this)
        t.text = text
        t.setTextColor(ash)
        t.textSize = 13f
        t.setPadding(0, 12, 0, 4)
        return t
    }

    private fun button(text: String, onTap: () -> Unit): Button {
        val b = Button(this)
        b.text = text
        b.setTextColor(amber)
        b.setBackgroundColor(Color.parseColor("#0B0F14"))
        b.gravity = Gravity.CENTER
        b.letterSpacing = 0.12f
        b.textSize = 13f
        b.setOnClickListener { onTap() }
        return b
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        refresh()
    }

    private fun toast(msg: String) { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show() }
}
