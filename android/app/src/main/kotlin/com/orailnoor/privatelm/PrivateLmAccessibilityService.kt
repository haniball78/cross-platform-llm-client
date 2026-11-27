package com.orailnoor.privatelm

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.Rect
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Accessibility hands for the on-device agent.
 *
 * The user enables this service manually in system Settings
 * (Settings > Accessibility > PrivateLM). It does nothing on its own:
 * it only acts when the app's agent (MainActivity agent channel) asks it
 * to, and only while an agent run the user explicitly started is in
 * progress. Every action is guarded, clamped to the screen, and logged.
 *
 * Coordinates cross the channel in dp so the model reasons in the same
 * units as the screen dump; they are converted to px here.
 */
class PrivateLmAccessibilityService : AccessibilityService() {

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // No passive automation: the service only acts on explicit agent
        // requests routed through MainActivity.
    }

    override fun onInterrupt() {
        Log.d(TAG, "interrupted")
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        Log.d(TAG, "connected")
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    // ── Actions, called from MainActivity on the main thread ──

    /** Tap at [xDp],[yDp] in dp. Returns false when the gesture is refused. */
    fun tap(xDp: Float, yDp: Float): Boolean {
        val (x, y) = clampPoint(xDp, yDp)
        val path = Path().apply { moveTo(x, y) }
        return dispatch(path, TAP_MS)
    }

    /** Swipe from one dp point to another over [durationMs] (100–3000). */
    fun swipe(x1Dp: Float, y1Dp: Float, x2Dp: Float, y2Dp: Float, durationMs: Long): Boolean {
        val (x1, y1) = clampPoint(x1Dp, y1Dp)
        val (x2, y2) = clampPoint(x2Dp, y2Dp)
        val path = Path().apply {
            moveTo(x1, y1)
            lineTo(x2, y2)
        }
        return dispatch(path, durationMs.coerceIn(100L, 3000L))
    }

    fun back(): Boolean = performGlobalAction(GLOBAL_ACTION_BACK)

    fun home(): Boolean = performGlobalAction(GLOBAL_ACTION_HOME)

    fun recents(): Boolean = performGlobalAction(GLOBAL_ACTION_RECENTS)

    /**
     * Clicks the first visible node whose text (or content description)
     * contains [text], walking up to the nearest clickable ancestor.
     */
    fun clickText(text: String): Boolean {
        val root = rootInActiveWindow ?: return false
        val node = findText(root, text) ?: return false
        var target: AccessibilityNodeInfo? = node
        var clicked = false
        while (target != null && !clicked) {
            if (target.isClickable) {
                clicked = target.performAction(AccessibilityNodeInfo.ACTION_CLICK)
            }
            target = target.parent
        }
        return clicked
    }

    /**
     * Compact screen dump for the agent's brain: one line per visible
     * labelled node, `text [left,top,right,bottom]` in dp, with a `*`
     * after the bounds when the node is clickable. Capped so the prompt
     * stays small.
     */
    fun dumpScreen(): String {
        val root = rootInActiveWindow ?: return ""
        val density = resources.displayMetrics.density
        val out = StringBuilder()
        var count = 0

        fun visit(node: AccessibilityNodeInfo?) {
            if (node == null || count >= MAX_DUMP_NODES || out.length > MAX_DUMP_CHARS) return
            val label = (node.text?.toString()?.trim().orEmpty())
                .ifEmpty { node.contentDescription?.toString()?.trim().orEmpty() }
            if (label.isNotEmpty()) {
                val r = Rect()
                node.getBoundsInScreen(r)
                val l = (r.left / density).toInt()
                val t = (r.top / density).toInt()
                val right = (r.right / density).toInt()
                val b = (r.bottom / density).toInt()
                out.append(label.replace('\n', ' ').take(60))
                out.append(" [$l,$t,$right,$b]")
                if (node.isClickable) out.append('*')
                out.append('\n')
                count++
            }
            for (i in 0 until node.childCount) visit(node.getChild(i))
        }

        visit(root)
        return out.toString()
    }

    // ── Helpers ──

    private fun dispatch(path: Path, durationMs: Long): Boolean {
        return try {
            val stroke = GestureDescription.StrokeDescription(path, 0, durationMs)
            val gesture = GestureDescription.Builder().addStroke(stroke).build()
            dispatchGesture(
                gesture,
                object : GestureResultCallback() {
                    override fun onCompleted(gestureDescription: GestureDescription?) {
                        Log.d(TAG, "gesture completed")
                    }

                    override fun onCancelled(gestureDescription: GestureDescription?) {
                        Log.w(TAG, "gesture cancelled")
                    }
                },
                null,
            )
        } catch (e: Exception) {
            Log.w(TAG, "dispatch failed", e)
            false
        }
    }

    /** dp → px, clamped inside the screen. */
    private fun clampPoint(xDp: Float, yDp: Float): Pair<Float, Float> {
        val metrics = resources.displayMetrics
        val x = (xDp * metrics.density).coerceIn(0f, (metrics.widthPixels - 1).toFloat())
        val y = (yDp * metrics.density).coerceIn(0f, (metrics.heightPixels - 1).toFloat())
        return x to y
    }

    private fun findText(node: AccessibilityNodeInfo?, text: String): AccessibilityNodeInfo? {
        if (node == null) return null
        val label = (node.text?.toString().orEmpty() + " " +
            node.contentDescription?.toString().orEmpty())
        if (label.contains(text, ignoreCase = true)) return node
        for (i in 0 until node.childCount) {
            val found = findText(node.getChild(i), text)
            if (found != null) return found
        }
        return null
    }

    companion object {
        private const val TAG = "PrivateLmA11y"
        private const val TAP_MS = 100L
        private const val MAX_DUMP_NODES = 80
        private const val MAX_DUMP_CHARS = 6000

        /** The running service, or null when the user has not enabled it. */
        @Volatile
        var instance: PrivateLmAccessibilityService? = null
            private set
    }
}
