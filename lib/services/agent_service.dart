import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:get/get.dart';

import '../core/constants.dart';
import 'cloud_service.dart';
import 'cluster_service.dart';
import 'hive_service.dart';
import 'inference_service.dart';

/// One answer from the brain, naming which model gave it.
class _BrainReply {
  /// 'local' or 'cloud'.
  final String brain;
  final String text;

  /// True when the cloud answered because the local model was missing
  /// or its reply was unusable.
  final bool escalated;

  const _BrainReply(this.brain, this.text, [this.escalated = false]);
}

/// Result of one tool loop, for the chat.
class ToolLoopResult {
  /// The model's final plain-text answer, or null when stopped early.
  final String? finalText;

  /// Visible 'used tool …' lines, in order.
  final List<String> toolUses;
  final bool stopped;
  final bool hitLimit;

  const ToolLoopResult({
    required this.finalText,
    required this.toolUses,
    required this.stopped,
    required this.hitLimit,
  });
}

/// Thrown when the accessibility service is not enabled on the phone.
class _AgentNotAvailable implements Exception {
  final String message;
  const _AgentNotAvailable(this.message);
}

/// Phone tools for the chat model, plus the brain that drives them.
///
/// The chat model — local AND cloud, both — gets two tools:
/// (1) accessibility: tap / swipe / click text / back / home / dump the
/// screen, through the `com.orailnoor.privatelm/agent` channel;
/// (2) wireless debugging: the phone's own wireless-debugging status,
/// the pairing port + code the user saved, and a read-only on-device
/// shell, all through the same `com.orailnoor.privatelm/agent` channel.
///
/// The brain mode decides which model answers each tool round:
/// 'both' (default) asks the loaded local model first and escalates to
/// the cloud provider when it is missing or its reply is unusable;
/// 'local' is on-device only; 'cloud' is the cloud provider only.
/// The tools only run inside [runToolLoop], which the chat starts for
/// one user message. Nothing here runs at boot or in the background
/// by itself.
class AgentService extends GetxService {
  static const _channel = MethodChannel('com.orailnoor.privatelm/agent');

  /// Max tool rounds per user message.
  static const maxToolRounds = 20;

  /// 'both' | 'local' | 'cloud'. Default 'both'.
  final brainMode = 'both'.obs;

  /// The user can turn the phone tools off entirely.
  final toolsEnabled = true.obs;

  String? _lastCloudProvider;

  @override
  void onInit() {
    super.onInit();
    final hive = Get.find<HiveService>();
    brainMode.value = hive.getSetting<String>(
          AppConstants.keyAgentBrainMode,
          defaultValue: 'both',
        ) ??
        'both';
    toolsEnabled.value = hive.getSetting<bool>(
          AppConstants.keyChatToolsEnabled,
          defaultValue: true,
        ) ??
        true;
  }

  Future<void> setBrainMode(String mode) async {
    if (mode != 'both' && mode != 'local' && mode != 'cloud') return;
    brainMode.value = mode;
    await Get.find<HiveService>()
        .setSetting(AppConstants.keyAgentBrainMode, mode);
  }

  Future<void> setToolsEnabled(bool value) async {
    toolsEnabled.value = value;
    await Get.find<HiveService>()
        .setSetting(AppConstants.keyChatToolsEnabled, value);
  }

  void toggleTools() => unawaited(setToolsEnabled(!toolsEnabled.value));

  // ── Tool loop ─────────────────────────────────────────────────────

  /// Runs one user message through the model with phone tools.
  ///
  /// [history] is the chat history INCLUDING the new user turn;
  /// [lastUserText] is that turn's text. The model may answer directly
  /// or call one tool per round; each tool result is fed back as the
  /// next message. Stops after [maxToolRounds] rounds, when the model
  /// answers in plain text, or when [shouldStop] turns true. Tool uses
  /// are reported through [onToolUse] as visible 'used tool …' lines.
  Future<ToolLoopResult> runToolLoop({
    required List<Map<String, String>> history,
    required String lastUserText,
    required String systemPrompt,
    void Function(String line)? onToolUse,
    bool Function()? shouldStop,
  }) async {
    final toolUses = <String>[];
    final messages = List<Map<String, String>>.from(history);
    var lastUserTurn = lastUserText;
    String? finalText;
    var stopped = false;
    var hitLimit = false;

    for (var round = 1; round <= maxToolRounds; round++) {
      if (shouldStop?.call() == true) {
        stopped = true;
        break;
      }
      final reply = await askModel(
        prompt: lastUserTurn,
        systemPrompt: _toolsSystemPrompt(systemPrompt),
        history: messages,
      );
      if (shouldStop?.call() == true) {
        stopped = true;
        break;
      }
      if (reply.escalated) {
        final note =
            'Brain: local model unavailable or unclear — using cloud (${_cloudLabel(_lastCloudProvider)}) instead.';
        toolUses.add(note);
        onToolUse?.call(note);
      }
      if (reply.text.startsWith('ERROR')) {
        finalText = reply.text;
        break;
      }
      final call = _parseToolCall(reply.text);
      if (call == null) {
        finalText = reply.text;
        break;
      }
      final result = await executeTool(call);
      final name = '${call['tool'] ?? call['action'] ?? ''}';
      final line =
          '🔧 used tool [${reply.brain}${reply.brain == 'cloud' ? '/${_cloudLabel(_lastCloudProvider)}' : ''}]: ${_describeTool(call)} → $result';
      toolUses.add(line);
      onToolUse?.call(line);
      messages.add({'role': 'assistant', 'content': reply.text});
      lastUserTurn = 'Tool $name result:\n$result\n'
          'Continue with the instruction. When done, reply with your '
          'final answer as plain text.';
      messages.add({'role': 'user', 'content': lastUserTurn});
      // Let the screen settle before the next dump.
      await Future.delayed(const Duration(milliseconds: 700));
      if (round == maxToolRounds) {
        hitLimit = true;
        finalText = reply.text;
      }
    }

    return ToolLoopResult(
      finalText: finalText,
      toolUses: toolUses,
      stopped: stopped,
      hitLimit: hitLimit,
    );
  }

  // ── Brain: local first, cloud on failure ──────────────────────────

  /// Answers one prompt with the brain selected by [brainMode].
  /// Local-first in 'both': when the local model is missing, or its
  /// reply tries to call a tool but the JSON is broken after one retry,
  /// the round escalates to the cloud provider.
  Future<_BrainReply> askModel({
    required String prompt,
    required String systemPrompt,
    List<Map<String, String>>? history,
  }) async {
    final mode = brainMode.value;
    if (mode == 'cloud') {
      return _BrainReply('cloud', await _askCloud(prompt, systemPrompt, history));
    }
    if (_hasLocalModel) {
      final reply = await _askLocal(prompt, systemPrompt, history);
      if (mode == 'local') return _BrainReply('local', reply);
      if (_looksLikeToolCall(reply) && _parseToolCall(reply) == null) {
        final retry = await _askLocal(
          '$prompt\nReply with only the JSON tool call, no other text.',
          systemPrompt,
          history,
        );
        if (_parseToolCall(retry) != null) return _BrainReply('local', retry);
        final cloud = await _askCloud(prompt, systemPrompt, history);
        return _BrainReply('cloud', cloud, true);
      }
      return _BrainReply('local', reply);
    }
    if (mode == 'local') {
      return const _BrainReply(
        'local',
        'ERROR: No local model loaded. Load a GGUF or LiteRT-LM model first.',
      );
    }
    final cloud = await _askCloud(prompt, systemPrompt, history);
    return _BrainReply('cloud', cloud, true);
  }

  bool get _hasLocalModel {
    if (!Get.isRegistered<InferenceService>()) return false;
    return Get.find<InferenceService>().isModelLoaded.value;
  }

  /// The already-loaded local model, same path the chat uses.
  Future<String> _askLocal(
    String prompt,
    String systemPrompt,
    List<Map<String, String>>? history,
  ) {
    return Get.find<InferenceService>().generate(
      prompt: prompt,
      systemPrompt: systemPrompt,
      conversationHistory: history,
      source: 'agent',
      maxTokens: 320,
    );
  }

  /// The cloud provider: Groq when its key is saved, otherwise the
  /// provider selected in Settings. Reports plainly when no key exists.
  Future<String> _askCloud(
    String prompt,
    String systemPrompt,
    List<Map<String, String>>? history,
  ) async {
    if (!Get.isRegistered<CloudService>()) {
      return 'ERROR: Cloud service is not available on this build.';
    }
    final cloud = Get.find<CloudService>();
    final provider = cloud.agentCloudProvider;
    if (provider == null) {
      return 'ERROR: No cloud API key saved. Add a Groq key (or another '
          'provider key) in Settings → Cloud.';
    }
    _lastCloudProvider = provider;
    return cloud.sendMessageAs(
      provider,
      messages: [
        {'role': 'system', 'content': systemPrompt},
        ...(history ?? []),
      ],
      maxTokens: 320,
    );
  }

  static const _cloudLabels = {
    'groq': 'Groq',
    'cerebras': 'Cerebras',
    'mistral': 'Mistral',
    'openrouter': 'OpenRouter',
    'deepseek': 'DeepSeek',
    'openai': 'OpenAI',
    'anthropic': 'Anthropic',
    'google': 'Gemini',
    'kimi': 'Kimi',
    'nvidia': 'NVIDIA',
    'custom': 'Custom',
  };

  String _cloudLabel(String? provider) =>
      _cloudLabels[provider] ?? provider ?? 'cloud';

  // ── Tool calls ────────────────────────────────────────────────────

  static const _toolsSystemPromptSuffix = '\n\nPhone tools — you can '
      'control this phone. To use one, reply with exactly one JSON '
      'object and no other text:\n'
      '{"tool":"tap","x":120,"y":300} — tap at dp coordinates;\n'
      '{"tool":"clickText","text":"Settings"} — tap the item with this text;\n'
      '{"tool":"swipe","x1":200,"y1":600,"x2":200,"y2":200};\n'
      '{"tool":"back"}; {"tool":"home"}; {"tool":"recents"};\n'
      '{"tool":"dumpScreen"} — lists visible texts with dp bounds '
      '(* = clickable); use it first when you need to see the screen;\n'
      '{"tool":"wirelessStatus"} — wireless debugging status: on/off, '
      'Wi-Fi IP, port, pairing;\n'
      '{"tool":"wirelessShell","command":"getprop ro.build.version.sdk"} — '
      'runs one read-only command on this phone (getprop, settings get, '
      'pm list, dumpsys, logcat, ip, ps). It runs as the app itself, so '
      'privileged commands fail; if you need those, ask the user to pair '
      'wireless debugging first.\n'
      'Tap only on coordinates from the dump. After a tool result, '
      'continue until done, then reply with your final answer as plain text.';

  String _toolsSystemPrompt(String base) => base + _toolsSystemPromptSuffix;

  bool _looksLikeToolCall(String reply) =>
      reply.contains('"tool"') || reply.contains('"action"');

  /// Extracts the first JSON object from the model reply, or null when
  /// there is no balanced `{...}` block in it. Tolerates ```json fences.
  Map<String, dynamic>? _parseToolCall(String reply) {
    var text = reply.trim();
    if (text.startsWith('```')) {
      final end = text.indexOf('```', 3);
      if (end > 3) text = text.substring(3, end).trim();
      if (text.startsWith('json')) text = text.substring(4).trim();
    }
    final start = text.indexOf('{');
    if (start < 0) return null;
    var depth = 0;
    var inString = false;
    var escaped = false;
    for (var i = start; i < text.length; i++) {
      final c = text[i];
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (c == '\\') {
          escaped = true;
        } else if (c == '"') {
          inString = false;
        }
        continue;
      }
      if (c == '"') {
        inString = true;
      } else if (c == '{') {
        depth++;
      } else if (c == '}') {
        depth--;
        if (depth == 0) {
          try {
            final decoded = jsonDecode(text.substring(start, i + 1));
            if (decoded is Map<String, dynamic>) {
              final tool = decoded['tool'] ?? decoded['action'];
              if (tool is String && tool.isNotEmpty) return decoded;
            }
          } catch (_) {
            return null;
          }
          return null;
        }
      }
    }
    return null;
  }

  /// Executes one parsed tool call and returns a short result string
  /// for the model. Never throws: failures are reported as text.
  Future<String> executeTool(Map<String, dynamic> call) async {
    final name = '${call['tool'] ?? call['action'] ?? ''}';
    try {
      switch (name) {
        case 'tap':
          final x = (call['x'] as num?)?.toDouble();
          final y = (call['y'] as num?)?.toDouble();
          if (x == null || y == null) return 'tap failed: x and y are required';
          final ok = await _callBool('agentTap', {'x': x, 'y': y});
          return ok ? 'tapped ($x, $y)' : 'tap failed';
        case 'swipe':
          final x1 = (call['x1'] as num?)?.toDouble();
          final y1 = (call['y1'] as num?)?.toDouble();
          final x2 = (call['x2'] as num?)?.toDouble();
          final y2 = (call['y2'] as num?)?.toDouble();
          if (x1 == null || y1 == null || x2 == null || y2 == null) {
            return 'swipe failed: x1, y1, x2, y2 are required';
          }
          final ok = await _callBool(
            'agentSwipe',
            {'x1': x1, 'y1': y1, 'x2': x2, 'y2': y2},
          );
          return ok ? 'swiped ($x1,$y1) → ($x2,$y2)' : 'swipe failed';
        case 'clickText':
          final text = '${call['text'] ?? ''}';
          if (text.isEmpty) return 'clickText failed: text is required';
          final ok = await _callBool('agentClickText', {'text': text});
          return ok ? 'clicked "$text"' : 'nothing matching "$text" found';
        case 'back':
          return await _callBool('agentBack') ? 'went back' : 'back failed';
        case 'home':
          return await _callBool('agentHome') ? 'went home' : 'home failed';
        case 'recents':
          return await _callBool('agentRecents')
              ? 'opened recents'
              : 'recents failed';
        case 'dumpScreen':
          final dump = await _dumpScreen();
          if (dump.isEmpty) {
            return 'Screen is empty or the accessibility service cannot read it.';
          }
          return 'Screen:\n$dump';
        case 'wirelessStatus':
          return wirelessStatus();
        case 'wirelessShell':
          final command = '${call['command'] ?? ''}'.trim();
          if (command.isEmpty) {
            return 'wirelessShell failed: command is required';
          }
          return wirelessShell(command);
        default:
          return 'Unknown tool "$name". Available tools: tap, clickText, '
              'swipe, back, home, recents, dumpScreen, wirelessStatus, '
              'wirelessShell.';
      }
    } on _AgentNotAvailable catch (e) {
      return e.message;
    } catch (e) {
      return 'Tool error: $e';
    }
  }

  // ── Wireless debugging (phone-only) ───────────────────────────────

  /// Wireless-debugging status for the model: the system toggle, the
  /// Wi-Fi IP, the adb port when the system exposes one, and the
  /// pairing info the user saved in the Server view. There is no full
  /// adb-protocol client in this build: the pairing handshake (SPAKE2 +
  /// TLS) and shell-as-shell-user are NOT implemented yet — the
  /// on-device shell below runs as the app itself.
  Future<String> wirelessStatus() async {
    final wifi = Get.isRegistered<ClusterService>()
        ? Get.find<ClusterService>().wifiAddress.value
        : null;
    final buffer = StringBuffer('Wireless debugging:\n');
    buffer.writeln('- Wi-Fi IP: ${wifi ?? 'not on Wi-Fi'}');
    var toggle = 'unknown';
    var port = '';
    try {
      final status =
          await _channel.invokeMethod<Map>('agentWirelessStatus');
      if (status != null) {
        toggle = status['wirelessDebugging'] == true ? 'ON' : 'OFF';
        port = '${status['adbTcpPort'] ?? ''}';
      }
    } catch (_) {}
    buffer.writeln('- Wireless debugging: $toggle');
    if (toggle == 'OFF') {
      buffer.writeln(
        '  Turn it on in Settings → Developer options → Wireless debugging.',
      );
    }
    buffer.writeln(
      '- ADB port: ${port.isEmpty ? 'not exposed by the system (wireless debugging uses a random port — enter it in the Server view)' : port}',
    );
    buffer.writeln('- Pairing: ${wirelessPairingSummary()}');
    return buffer.toString().trim();
  }

  /// Runs one read-only command on this phone, as the app itself.
  /// The native side enforces the allowlist and the timeout; anything
  /// else comes back as an error string.
  Future<String> wirelessShell(String command) async {
    final out =
        await _callString('agentWirelessShell', {'command': command});
    return out.isEmpty ? 'wirelessShell failed: no output' : out;
  }

  /// The pairing port + code the user typed in the Server view, or a
  /// plain line saying none is saved yet.
  String wirelessPairingSummary() {
    final hive =
        Get.isRegistered<HiveService>() ? Get.find<HiveService>() : null;
    final port = hive?.getSetting<String>(
          AppConstants.keyWirelessPairPort,
          defaultValue: '',
        ) ??
        '';
    final code = hive?.getSetting<String>(
          AppConstants.keyWirelessPairCode,
          defaultValue: '',
        ) ??
        '';
    if (port.isEmpty || code.isEmpty) {
      return 'not saved — enter the port + 6-digit code from Developer '
          'options → Wireless debugging in the Server view';
    }
    return 'saved (port $port, code ••••••) — the pairing handshake is '
        'not implemented in this build yet, so the app cannot connect '
        'as a wireless-debugging client yet';
  }

  /// Saves the pairing port + 6-digit code the user typed. Returns an
  /// error string, or null on success.
  Future<String?> saveWirelessPairing({
    required String port,
    required String code,
  }) async {
    final p = int.tryParse(port.trim());
    if (p == null || p < 1 || p > 65535) return 'Port must be 1–65535.';
    if (!RegExp(r'^\d{6}$').hasMatch(code.trim())) {
      return 'Pairing code must be the 6 digits shown on the phone.';
    }
    final hive = Get.find<HiveService>();
    await hive.setSetting(AppConstants.keyWirelessPairPort, port.trim());
    await hive.setSetting(AppConstants.keyWirelessPairCode, code.trim());
    return null;
  }

  Future<void> clearWirelessPairing() async {
    final hive = Get.find<HiveService>();
    await hive.setSetting(AppConstants.keyWirelessPairPort, '');
    await hive.setSetting(AppConstants.keyWirelessPairCode, '');
  }

  String _describeTool(Map<String, dynamic> call) {
    final name = '${call['tool'] ?? call['action'] ?? ''}';
    switch (name) {
      case 'tap':
        return 'tap ${call['x']},${call['y']}';
      case 'swipe':
        return 'swipe ${call['x1']},${call['y1']} → ${call['x2']},${call['y2']}';
      case 'clickText':
        return 'click "${call['text'] ?? ''}"';
      case 'back':
        return 'back';
      case 'home':
        return 'home';
      case 'recents':
        return 'recents';
      case 'dumpScreen':
        return 'dumpScreen';
      case 'wirelessStatus':
        return 'wirelessStatus';
      case 'wirelessShell':
        return 'wirelessShell "${call['command'] ?? ''}"';
      default:
        return name;
    }
  }

  // ── Hands: one channel call per action ──

  /// One channel call that returns a string (wireless tools).
  Future<String> _callString(String method,
      [Map<String, dynamic>? args]) async {
    try {
      return await _channel.invokeMethod<String>(method, args) ?? '';
    } catch (_) {
      return '';
    }
  }

  Future<bool> _callBool(String method,
      [Map<String, dynamic>? args]) async {
    try {
      return await _channel.invokeMethod<bool>(method, args) ?? false;
    } on PlatformException catch (e) {
      if (e.code == 'SERVICE_NOT_ENABLED') {
        throw const _AgentNotAvailable(
          'Accessibility service is not enabled. '
          'Enable PrivateLM in Settings → Accessibility first.',
        );
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  Future<String> _dumpScreen() async {
    try {
      return await _channel.invokeMethod<String>('agentDumpScreen') ?? '';
    } on PlatformException catch (e) {
      if (e.code == 'SERVICE_NOT_ENABLED') {
        throw const _AgentNotAvailable(
          'Accessibility service is not enabled. '
          'Enable PrivateLM in Settings → Accessibility first.',
        );
      }
      return '';
    } catch (_) {
      return '';
    }
  }
}
