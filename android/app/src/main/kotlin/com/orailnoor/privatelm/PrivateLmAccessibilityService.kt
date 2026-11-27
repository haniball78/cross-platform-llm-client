package com.orailnoor.privatelm

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent

/**
 * Accessibility entry point for PrivateLM.
 *
 * The user enables this service manually in system Settings
 * (Settings > Accessibility > PrivateLM). It performs no automation and
 * takes no action on events: it exists only so the app can be granted
 * accessibility access, e.g. to keep working while the user is in
 * another app.
 */
class PrivateLmAccessibilityService : AccessibilityService() {

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Intentionally a no-op: no automation, no taps, no reading of
        // window content. Kept only for the debug log below.
        Log.d(TAG, "event: ${event?.eventType}")
    }

    override fun onInterrupt() {
        Log.d(TAG, "interrupted")
    }

    companion object {
        private const val TAG = "PrivateLmA11y"
    }
}
