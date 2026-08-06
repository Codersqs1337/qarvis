package com.qasim.qarvis

import android.content.Context
import android.content.Intent
import android.hardware.camera2.CameraManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.telecom.TelecomManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class Outcome(val spoken: String, val action: (() -> Unit)? = null)

class CommandRouter(private val ctx: Context) {

    private val owner = "Qasim"

    private val apps: Map<String, Pair<String, List<String>>> = mapOf(
        "whatsapp" to ("WhatsApp" to listOf("com.whatsapp", "com.whatsapp.w4b")),
        "chrome" to ("Chrome" to listOf("com.android.chrome")),
        "firefox" to ("Firefox" to listOf("org.mozilla.firefox", "org.mozilla.fenix")),
        "instagram" to ("Instagram" to listOf("com.instagram.android")),
        "facebook" to ("Facebook" to listOf("com.facebook.katana")),
        "telegram" to ("Telegram" to listOf("org.telegram.messenger")),
        "youtube" to ("YouTube" to listOf("com.google.android.youtube")),
        "gallery" to ("Gallery" to listOf("com.google.android.apps.photos", "com.sec.android.gallery3d", "com.miui.gallery", "com.android.gallery3d")),
        "camera" to ("Camera" to listOf("com.google.android.GoogleCamera", "com.sec.android.app.camera", "com.android.camera2")),
        "maps" to ("Maps" to listOf("com.google.android.apps.maps")),
        "gmail" to ("Gmail" to listOf("com.google.android.gm")),
        "spotify" to ("Spotify" to listOf("com.spotify.music")),
        "twitter" to ("X" to listOf("com.twitter.android")),
        "linkedin" to ("LinkedIn" to listOf("com.linkedin.android")),
        "github" to ("GitHub" to listOf("com.github.android")),
        "phone" to ("Phone" to listOf("com.google.android.dialer", "com.android.dialer")),
        "messages" to ("Messages" to listOf("com.google.android.apps.messaging")),
        "termux" to ("Termux" to listOf("com.termux"))
    )

    private val aliases = mapOf(
        "whats app" to "whatsapp", "what's app" to "whatsapp", "whatsup" to "whatsapp",
        "insta" to "instagram", "photos" to "gallery", "pictures" to "gallery",
        "images" to "gallery", "browser" to "chrome", "google chrome" to "chrome",
        "fire fox" to "firefox", "you tube" to "youtube", "x" to "twitter",
        "g mail" to "gmail", "mail" to "gmail", "email" to "gmail",
        "dialer" to "phone", "map" to "maps", "text messages" to "messages",
        "sms" to "messages", "music" to "spotify"
    )

    private val blocked = listOf(
        "bank", "banking", "paypal", "wallet", "payoneer", "wise", "revolut",
        "stripe", "crypto", "binance", "coinbase", "easypaisa", "jazzcash",
        "upi", "paytm", "venmo", "cash app", "credit card", "debit card"
    )

    fun run(raw: String): Outcome {
        val c = raw.lowercase(Locale.US).trim()
        if (c.isEmpty()) return Outcome("I did not hear anything.")

        if (blocked.any { c.contains(it) }) {
            return Outcome("Financial apps are outside my access, $owner. That was your rule.")
        }

        Regex("\\b(?:open|launch|start|run|show)\\s+(.+)").find(c)?.let { m ->
            val key = resolve(m.groupValues[1]) ?: return Outcome("I do not have that app in my registry.")
            val pair = apps.getValue(key)
            val intent = pair.second.firstNotNullOfOrNull { p ->
                ctx.packageManager.getLaunchIntentForPackage(p)
            } ?: return Outcome(pair.first + " is not installed on this phone.")
            return Outcome("Opening " + pair.first) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(intent)
            }
        }

        Regex("\\b(?:search|google|look up|find)\\s+(?:for\\s+)?(.+)").find(c)?.let { m ->
            val q = m.groupValues[1]
            return Outcome("Searching $q") { web("https://www.google.com/search?q=" + Uri.encode(q)) }
        }

        Regex("\\bplay\\s+(.+?)(?:\\s+on youtube)?$").find(c)?.let { m ->
            val q = m.groupValues[1]
            return Outcome("Playing $q") { web("https://www.youtube.com/results?search_query=" + Uri.encode(q)) }
        }

        Regex("\\b(?:call|dial)\\s+([\\d\\s]{4,})").find(c)?.let { m ->
            val number = m.groupValues[1].replace(" ", "")
            return Outcome("Dialling $number") {
                ctx.startActivity(Intent(Intent.ACTION_CALL, Uri.parse("tel:$number")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
        }

        if (Regex("\\banswer\\b").containsMatchIn(c)) {
            return Outcome("Answering") { answerCall() }
        }

        if (c.contains("flashlight") || c.contains("torch")) {
            val on = !c.contains("off")
            return Outcome(if (on) "Torch on" else "Torch off") { torch(on) }
        }

        if (c.contains("settings")) {
            return Outcome("Opening settings") {
                ctx.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
        }

        if (c.contains("time")) {
            return Outcome("It is " + SimpleDateFormat("h:mm a", Locale.US).format(Date()))
        }

        if (c.contains("date") || c.contains("what day")) {
            return Outcome("Today is " + SimpleDateFormat("EEEE, d MMMM", Locale.US).format(Date()))
        }

        if (c.contains("battery")) {
            return Outcome("Battery is at " + battery() + " percent")
        }

        if (c.contains("who are you") || c.contains("your name")) {
            return Outcome("I am Qarvis, $owner. Your personal voice assistant. Apps, search, calls and messages. No files, no finance.")
        }

        if (c.contains("what can you do") || c.contains("help")) {
            return Outcome("Say: open WhatsApp. Search something. Call a number. Answer the call. Torch on. Ask the time or the battery.")
        }

        if (Regex("\\b(sleep|stand down|stop|goodbye|dismiss|never mind)\\b").containsMatchIn(c)) {
            return Outcome("Standing by.")
        }

        return Outcome("I did not catch a command in that, $owner.")
    }

    private fun resolve(rawName: String): String? {
        val s = rawName.replace(Regex("^(the|my)\\s+"), "").replace(Regex("\\s+(app|application)$"), "").trim()
        aliases[s]?.let { return it }
        if (apps.containsKey(s)) return s
        apps.keys.firstOrNull { s.contains(it) }?.let { return it }
        aliases.keys.firstOrNull { s.contains(it) }?.let { return aliases[it] }
        return null
    }

    private fun web(url: String) {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    private fun answerCall() {
        try {
            val tm = ctx.getSystemService(Context.TELECOM_SERVICE) as TelecomManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) tm.acceptRingingCall()
        } catch (e: Exception) {}
    }

    private fun torch(on: Boolean) {
        try {
            val cm = ctx.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            val id = cm.cameraIdList.firstOrNull() ?: return
            cm.setTorchMode(id, on)
        } catch (e: Exception) {}
    }

    private fun battery(): Int {
        return try {
            val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as android.os.BatteryManager
            bm.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
        } catch (e: Exception) { -1 }
    }
}
