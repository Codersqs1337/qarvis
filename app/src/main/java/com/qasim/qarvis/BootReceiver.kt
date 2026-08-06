package com.qasim.qarvis

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Brings Qarvis back after a reboot. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED || action == "android.intent.action.QUICKBOOT_POWERON") {
            if (Prefs.accessKey(ctx).isBlank()) return
            ctx.startForegroundService(Intent(ctx, QarvisService::class.java))
        }
    }
}
