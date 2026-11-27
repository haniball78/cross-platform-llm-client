import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:get/get.dart';

import '../controllers/server_controller.dart';

/// Draw-over-apps bubble and the system permission shortcuts behind it.
///
/// All platform work lives in MainActivity / BubbleService behind one
/// MethodChannel; this service only forwards calls and keeps the granted /
/// running state as observables for Settings.
class OverlayService extends GetxService with WidgetsBindingObserver {
  static const _channel = MethodChannel('com.orailnoor.privatelm/overlay');

  @override
  void onInit() {
    super.onInit();
    // The overlay-permission row must re-read the granted flag when the
    // user comes back from the system Settings screen, where the grant
    // actually happens. refreshStatus() right after opening Settings
    // runs too early and still reads "not granted".
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) unawaited(refreshStatus());
  }

  @override
  void onClose() {
    WidgetsBinding.instance.removeObserver(this);
    super.onClose();
  }

  /// Whether the user granted "Draw over other apps" to PrivateLM.
  final canDrawOverlays = false.obs;

  /// Whether the floating bubble is on screen right now.
  final isBubbleRunning = false.obs;

  /// Reads both flags from the platform. Safe to call when the channel
  /// has no handler (e.g. web): everything defaults to false.
  Future<bool> refreshStatus() async {
    try {
      canDrawOverlays.value =
          await _channel.invokeMethod<bool>('canDrawOverlays') ?? false;
      isBubbleRunning.value =
          await _channel.invokeMethod<bool>('isBubbleRunning') ?? false;
    } catch (_) {
      canDrawOverlays.value = false;
      isBubbleRunning.value = false;
    }
    return canDrawOverlays.value;
  }

  /// Opens the system "Draw over other apps" screen for PrivateLM, then
  /// re-reads the granted flag when the user comes back.
  Future<void> requestOverlayPermission() async {
    try {
      await _channel.invokeMethod('requestOverlayPermission');
    } catch (_) {}
    await refreshStatus();
  }

  /// Opens the system Accessibility settings, where the user enables
  /// PrivateLM by hand. Android never lets an app enable this itself.
  Future<void> openAccessibilitySettings() async {
    try {
      await _channel.invokeMethod('openAccessibilitySettings');
    } catch (_) {}
  }

  /// Shows the floating bubble. Throws a PlatformException when the
  /// overlay permission is not granted yet.
  Future<void> startBubble() async {
    final serving = Get.isRegistered<ServerController>()
        ? Get.find<ServerController>().isRunning.value
        : false;
    await _channel.invokeMethod('setServerRunning', {'running': serving});
    await _channel.invokeMethod('startBubble');
    await refreshStatus();
  }

  /// Hides the floating bubble.
  Future<void> stopBubble() async {
    try {
      await _channel.invokeMethod('stopBubble');
    } catch (_) {}
    await refreshStatus();
  }

  /// Tells the bubble whether the local API server is serving, so its
  /// dot turns green. Called with the server state when the bubble starts,
  /// and by ServerController whenever the server starts or stops.
  Future<void> setServerRunning(bool running) async {
    try {
      await _channel.invokeMethod('setServerRunning', {'running': running});
    } catch (_) {}
  }
}
