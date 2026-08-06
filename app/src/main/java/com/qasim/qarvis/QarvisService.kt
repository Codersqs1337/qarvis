package com.qasim.qarvis

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import android.util.Log
import ai.picovoice.porcupine.Porcupine
import ai.picovoice.porcupine.PorcupineManager
import org.json.JSONObject
import org.vosk.Model
import org.vosk.Recognizer
import org.vosk.android.RecognitionListener
import org.vosk.android.SpeechService
import org.vosk.android.StorageService
import java.io.File
import java.util.Locale

class QarvisService : Service(), RecognitionListener {

    companion object {
        const val TAG = "Qarvis"
        const val CHANNEL_ID = "qarvis_core"
        const val NOTIFICATION_ID = 7

        @Volatile var isRunning = false
        @Volatile var status: String = "stopped"
    }

    private var porcupine: PorcupineManager? = null
    private var voskModel: Model? = null
    private var voskService: SpeechService? = null
    private var tts: TextToSpeech? = null
    private var hud: HudOverlay? = null
    private var wakeLock: PowerManager.WakeLock? = null

    private val ui = Handler(Looper.getMainLooper())
    private lateinit var router: CommandRouter

    private var capturing = false
    private var captureTimeout: Runnable? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        isRunning = true
        router = CommandRouter(this)

        createChannel()
        startForeground(NOTIFICATION_ID, notification("Starting up"))

        wakeLock = (getSystemService(POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "qarvis:listener")
            .apply { setReferenceCounted(false); acquire() }

        tts = TextToSpeech(this) { state ->
            if (state == TextToSpeech.SUCCESS) {
                tts?.language = Locale.US
                tts?.setSpeechRate(1.0f)
                tts?.setPitch(0.92f)
            }
        }

        loadVoskModel()
        startWakeWord()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        isRunning = false
        status = "stopped"
        stopCapture()
        try { porcupine?.stop(); porcupine?.delete() } catch (e: Exception) {}
        porcupine = null
        tts?.shutdown()
        hud?.hide()
        try { wakeLock?.release() } catch (e: Exception) {}
        voskModel?.close()
        super.onDestroy()
    }

    private fun startWakeWord() {
        val key = Prefs.accessKey(this)
        if (key.isBlank()) {
            setStatus("No Picovoice key - open the app and paste one")
            return
        }
        try {
            val builder = PorcupineManager.Builder()
                .setAccessKey(key)
                .setSensitivity(0.65f)

            val custom = File(filesDir, "qarvis.ppn")
            if (custom.exists()) {
                builder.setKeywordPath(custom.absolutePath)
            } else {
                builder.setKeyword(Porcupine.BuiltInKeyword.JARVIS)
            }

            porcupine = builder.build(applicationContext) { onWakeWord() }
            porcupine?.start()
            setStatus("Standing by")
        } catch (e: Exception) {
            Log.e(TAG, "wake word failed", e)
            setStatus("Wake word error: " + e.message)
        }
    }

    private fun onWakeWord() {
        ui.post {
            if (capturing) return@post
            try { porcupine?.stop() } catch (e: Exception) {}

            hud = HudOverlay(this).also { it.show() }
            hud?.setState("QARVIS")
            setStatus("Awake")

            speak("Hello Qasim. I am Qarvis, your personal voice assistant. Tell me what you want.") {
                startCapture()
            }
        }
    }

    private fun loadVoskModel() {
        StorageService.unpack(this, "model-en-us", "model",
            { model -> voskModel = model; Log.i(TAG, "vosk model ready") },
            { e -> Log.e(TAG, "vosk model failed", e) }
        )
    }

    private fun startCapture() {
        val model = voskModel
        if (model == null) {
            endSession("The speech model is still loading. Try again in a moment.")
            return
        }
        try {
            val recognizer = Recognizer(model, 16000.0f)
            voskService = SpeechService(recognizer, 16000.0f)
            voskService?.startListening(this)
            capturing = true
            hud?.setState("LISTENING")
            hud?.setCaption("")

            captureTimeout = Runnable {
                if (capturing) {
                    stopCapture()
                    endSession("I did not catch a command, Qasim.")
                }
            }
            ui.postDelayed(captureTimeout!!, 9000)
        } catch (e: Exception) {
            Log.e(TAG, "capture failed", e)
            endSession("Microphone is busy.")
        }
    }

    private fun stopCapture() {
        capturing = false
        captureTimeout?.let { ui.removeCallbacks(it) }
        captureTimeout = null
        try { voskService?.stop() } catch (e: Exception) {}
        try { voskService?.shutdown() } catch (e: Exception) {}
        voskService = null
    }

    private fun heard(json: String?): String {
        if (json.isNullOrBlank()) return ""
        return try {
            val o = JSONObject(json)
            (if (o.has("text")) o.optString("text") else o.optString("partial")).trim()
        } catch (e: Exception) { "" }
    }

    override fun onPartialResult(hypothesis: String?) {
        val text = heard(hypothesis)
        if (text.isNotEmpty()) hud?.setCaption(text)
    }

    override fun onResult(hypothesis: String?) {
        val text = heard(hypothesis)
        if (text.isEmpty() || !capturing) return
        stopCapture()
        execute(text)
    }

    override fun onFinalResult(hypothesis: String?) {
        val text = heard(hypothesis)
        if (text.isEmpty() || !capturing) return
        stopCapture()
        execute(text)
    }

    override fun onError(e: Exception?) {
        Log.e(TAG, "vosk error", e)
        stopCapture()
        endSession("Something went wrong with the microphone.")
    }

    override fun onTimeout() {
        stopCapture()
        endSession("I did not catch a command, Qasim.")
    }

    private fun execute(text: String) {
        hud?.setState("EXECUTING")
        hud?.setCaption(text)
        val outcome = router.run(text)
        speak(outcome.spoken) {
            try { outcome.action?.invoke() } catch (e: Exception) { Log.e(TAG, "action failed", e) }
            endSession(null)
        }
    }

    private fun endSession(spoken: String?) {
        if (spoken != null) speak(spoken) { closeHud() } else closeHud()
    }

    private fun closeHud() {
        ui.postDelayed({
            hud?.hide()
            hud = null
            try { porcupine?.start(); setStatus("Standing by") } catch (e: Exception) {
                setStatus("Wake word stopped - restart the service")
            }
        }, 500)
    }

    private fun speak(text: String, then: (() -> Unit)?) {
        hud?.setCaption(text)
        val engine = tts
        if (engine == null) {
            ui.postDelayed({ then?.invoke() }, 900)
            return
        }
        val id = "qarvis-" + System.currentTimeMillis()
        var fired = false
        val finish = { if (!fired) { fired = true; ui.post { then?.invoke() } } }
        engine.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
            override fun onStart(utteranceId: String?) {}
            override fun onDone(utteranceId: String?) { finish() }
            override fun onError(utteranceId: String?) { finish() }
        })
        val result = engine.speak(text, TextToSpeech.QUEUE_FLUSH, null, id)
        if (result != TextToSpeech.SUCCESS) ui.postDelayed({ finish() }, 900)
        ui.postDelayed({ finish() }, 12000)
    }

    private fun createChannel() {
        val mgr = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(CHANNEL_ID, "Qarvis listener", NotificationManager.IMPORTANCE_LOW)
        channel.description = "Keeps Qarvis listening for the wake word"
        channel.setShowBadge(false)
        mgr.createNotificationChannel(channel)
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Qarvis")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_qarvis)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun setStatus(text: String) {
        status = text
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
        } catch (e: Exception) {}
    }
}
