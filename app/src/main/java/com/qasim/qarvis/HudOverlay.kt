package com.qasim.qarvis

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.RectF
import android.os.Build
import android.view.View
import android.view.WindowManager
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

class HudOverlay(private val ctx: Context) {

    private val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private var view: HudView? = null

    fun show() {
        if (view != null) return
        val v = HudView(ctx)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        else
            WindowManager.LayoutParams.TYPE_PHONE

        val flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            type, flags, PixelFormat.TRANSLUCENT
        )
        try {
            wm.addView(v, params)
            view = v
        } catch (e: Exception) {
        }
    }

    fun hide() {
        view?.let { try { wm.removeView(it) } catch (e: Exception) {} }
        view = null
    }

    fun setState(text: String) { view?.state = text; view?.postInvalidate() }
    fun setCaption(text: String) { view?.caption = text; view?.postInvalidate() }
}

private class HudView(ctx: Context) : View(ctx) {

    var state: String = "QARVIS"
    var caption: String = ""

    private val amber = Color.parseColor("#FFB000")
    private val ice = Color.parseColor("#4FD6E8")
    private val start = System.currentTimeMillis()

    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 4f
    }
    private val tick = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 3f
    }
    private val big = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        isFakeBoldText = true
    }
    private val small = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
    }

    override fun onDraw(canvas: Canvas) {
        val t = (System.currentTimeMillis() - start).toFloat()
        val w = width.toFloat()
        val h = height.toFloat()
        val cx = w / 2f
        val cy = h * 0.42f
        val r = min(w, h) * 0.22f

        canvas.drawColor(Color.argb(232, 5, 7, 10))

        val accent = if (state == "LISTENING") ice else amber

        tick.color = Color.argb(90, Color.red(accent), Color.green(accent), Color.blue(accent))
        for (i in 0 until 60) {
            val a = (i / 60f) * 2f * Math.PI.toFloat() + t / 9000f
            val long = i % 5 == 0
            val r1 = r * 1.35f
            val r2 = r1 - if (long) 22f else 11f
            canvas.drawLine(cx + cos(a) * r1, cy + sin(a) * r1, cx + cos(a) * r2, cy + sin(a) * r2, tick)
        }

        ring.color = Color.argb(60, Color.red(accent), Color.green(accent), Color.blue(accent))
        canvas.drawCircle(cx, cy, r, ring)

        ring.color = accent
        val box = RectF(cx - r, cy - r, cx + r, cy + r)
        val sweep = (t / 6f) % 360f
        canvas.drawArc(box, sweep, 70f, false, ring)
        canvas.drawArc(box, sweep + 180f, 40f, false, ring)

        val pulse = r * (0.42f + 0.06f * sin(t / 260f))
        ring.color = Color.argb(150, Color.red(accent), Color.green(accent), Color.blue(accent))
        canvas.drawCircle(cx, cy, pulse, ring)

        big.color = accent
        big.textSize = r * 0.42f
        canvas.drawText(state, cx, cy + big.textSize * 0.35f, big)

        small.color = Color.parseColor("#E8E2D6")
        small.textSize = r * 0.23f
        if (caption.isNotEmpty()) {
            wrap(caption, w * 0.82f, small).forEachIndexed { i, line ->
                canvas.drawText(line, cx, cy + r * 1.9f + i * small.textSize * 1.35f, small)
            }
        }

        small.color = Color.argb(120, 92, 102, 114)
        small.textSize = r * 0.16f
        canvas.drawText("QARVIS  -  OFFLINE", cx, h * 0.93f, small)

        postInvalidateOnAnimation()
    }

    private fun wrap(text: String, maxWidth: Float, paint: Paint): List<String> {
        val words = text.split(" ")
        val lines = ArrayList<String>()
        var line = StringBuilder()
        for (word in words) {
            val candidate = if (line.isEmpty()) word else "$line $word"
            if (paint.measureText(candidate) > maxWidth && line.isNotEmpty()) {
                lines.add(line.toString())
                line = StringBuilder(word)
            } else {
                line = StringBuilder(candidate)
            }
            if (lines.size >= 3) break
        }
        if (line.isNotEmpty() && lines.size < 4) lines.add(line.toString())
        return lines
    }
}
