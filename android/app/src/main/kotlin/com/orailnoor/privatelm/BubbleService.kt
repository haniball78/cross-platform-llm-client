package com.orailnoor.privatelm

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.TextView

/**
 * Draggable floating bubble over other apps. Tap opens PrivateLM,
 * long-press stops the bubble. Never starts without the draw-over-apps
 * permission. Green while the local API server serves a model, grey
 * while it is stopped ([serverRunning], set from Dart).
 */
class BubbleService : Service() {

    private var windowManager: WindowManager? = null
    private var bubble: TextView? = null
    private var params: WindowManager.LayoutParams? = null
    private val handler = Handler(Looper.getMainLooper())
    private var longPressRunnable: Runnable? = null

    override fun onCreate() {
        super.onCreate()
        if (!Settings.canDrawOverlays(this)) {
            Log.w(TAG, "no overlay permission, stopping")
            stopSelf()
            return
        }
        isRunning = true
        startForeground(NOTIFICATION_ID, buildNotification())
        showBubble()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        updateBubble()
        return START_STICKY
    }

    override fun onDestroy() {
        isRunning = false
        longPressRunnable?.let { handler.removeCallbacks(it) }
        try {
            bubble?.let { windowManager?.removeView(it) }
        } catch (e: Exception) {
            Log.w(TAG, "removeView failed", e)
        }
        bubble = null
        windowManager = null
        stopForeground(true)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun buildNotification(): Notification {
        val channelId = "privatelm_bubble"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "PrivateLM bubble",
                NotificationManager.IMPORTANCE_LOW
            )
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launchIntent?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }
        val stopIntent = Intent(this, BubbleService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, channelId)
            .setContentTitle("PrivateLM bubble")
            .setContentText("Tap the bubble to open PrivateLM")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .apply { if (pending != null) setContentIntent(pending) }
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop bubble",
                stopPending
            )
            .build()
    }

    private fun showBubble() {
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        windowManager = wm
        val view = TextView(this).apply {
            text = bubbleText()
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            gravity = Gravity.CENTER
            val pad = dp(14)
            setPadding(pad, pad, pad, pad)
            background = bubbleBackground()
        }
        val layoutParams = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            x = prefs.getInt(KEY_X, 0)
            y = prefs.getInt(KEY_Y, dp(300))
        }
        params = layoutParams
        clampParams()
        bubble = view
        view.setOnTouchListener(BubbleTouchListener())
        try {
            wm.addView(view, layoutParams)
        } catch (e: Exception) {
            Log.w(TAG, "addView failed", e)
            isRunning = false
            stopSelf()
        }
    }

    private fun updateBubble() {
        val view = bubble ?: return
        view.text = bubbleText()
        view.background = bubbleBackground()
    }

    private fun bubbleText(): String = if (serverRunning) "● LM" else "LM"

    private fun bubbleBackground(): GradientDrawable {
        val fill = if (serverRunning) 0xFF2E7D32.toInt() else 0xFF0F766E.toInt()
        return GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(fill)
            setStroke(dp(2), Color.WHITE)
        }
    }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics
        ).toInt()

    private fun displaySize(): Pair<Int, Int> {
        val wm = windowManager ?: return 0 to 0
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bounds = wm.currentWindowMetrics.bounds
            bounds.width() to bounds.height()
        } else {
            @Suppress("DEPRECATION")
            val size = android.graphics.Point()
            @Suppress("DEPRECATION")
            wm.defaultDisplay.getSize(size)
            size.x to size.y
        }
    }

    /** Keeps the bubble fully on screen (also clamps a restored position). */
    private fun clampParams() {
        val p = params ?: return
        val (w, h) = displaySize()
        val bw = bubble?.width?.takeIf { it > 0 } ?: dp(60)
        val bh = bubble?.height?.takeIf { it > 0 } ?: dp(60)
        p.x = p.x.coerceIn(0, (w - bw).coerceAtLeast(0))
        p.y = p.y.coerceIn(0, (h - bh).coerceAtLeast(0))
    }

    private fun savePosition() {
        val p = params ?: return
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt(KEY_X, p.x)
            .putInt(KEY_Y, p.y)
            .apply()
    }

    private fun openApp() {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        if (intent != null) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
        }
    }

    private inner class BubbleTouchListener : View.OnTouchListener {
        private var downX = 0f
        private var downY = 0f
        private var startX = 0
        private var startY = 0
        private var downTime = 0L
        private var moved = false

        override fun onTouch(v: View, event: MotionEvent): Boolean {
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    downX = event.rawX
                    downY = event.rawY
                    startX = params?.x ?: 0
                    startY = params?.y ?: 0
                    downTime = System.currentTimeMillis()
                    moved = false
                    val stop = Runnable { stopSelf() }
                    longPressRunnable = stop
                    handler.postDelayed(stop, LONG_PRESS_MS)
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = (event.rawX - downX).toInt()
                    val dy = (event.rawY - downY).toInt()
                    if (!moved && (kotlin.math.abs(dx) > DRAG_PX || kotlin.math.abs(dy) > DRAG_PX)) {
                        moved = true
                        longPressRunnable?.let { handler.removeCallbacks(it) }
                    }
                    if (moved) {
                        params?.x = startX + dx
                        params?.y = startY + dy
                        clampParams()
                        bubble?.let { windowManager?.updateViewLayout(it, params) }
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    longPressRunnable?.let { handler.removeCallbacks(it) }
                    longPressRunnable = null
                    savePosition()
                    val held = System.currentTimeMillis() - downTime
                    if (!moved && held < LONG_PRESS_MS) openApp()
                }
            }
            return true
        }
    }

    companion object {
        private const val TAG = "BubbleService"
        private const val NOTIFICATION_ID = 101
        private const val LONG_PRESS_MS = 600L
        private const val DRAG_PX = 15

        const val ACTION_STOP = "com.orailnoor.privatelm.STOP_BUBBLE"

        private const val PREFS = "privatelm_bubble"
        private const val KEY_X = "bubble_x"
        private const val KEY_Y = "bubble_y"

        /** True while the local API server is serving a model. Set from Dart. */
        @Volatile
        var serverRunning: Boolean = false

        /** True while the bubble is on screen. Read from Dart. */
        @Volatile
        var isRunning: Boolean = false
    }
}
