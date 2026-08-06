package com.qasim.qarvis

import android.content.Context

/** One tiny place to keep the Picovoice AccessKey. */
object Prefs {
    private const val FILE = "qarvis"
    private const val KEY = "access_key"

    fun accessKey(ctx: Context): String =
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).getString(KEY, "") ?: ""

    fun setAccessKey(ctx: Context, value: String) {
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().putString(KEY, value.trim()).apply()
    }
}
