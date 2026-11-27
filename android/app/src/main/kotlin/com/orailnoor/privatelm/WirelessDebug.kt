package com.orailnoor.privatelm

import android.content.Context
import android.provider.Settings
import java.util.concurrent.TimeUnit

/**
 * On-device wireless debugging, phone-only.
 *
 * Two paths live here: the full adb wireless client in
 * [AdbWireless] (pairing handshake + shell-as-shell-user through
 * adbd), and this file's read-only shell as the app itself
 * (Runtime.exec, app UID), which is the fallback when the phone
 * is not paired. [AdbWireless.shell] says which path ran.
 */
object WirelessDebug {

    /** Read-only commands the chat model may run. */
    private val allowedCommands = setOf(
        "getprop", "settings", "pm", "dumpsys", "logcat", "ip", "ps"
    )

    private const val MAX_COMMAND_CHARS = 400

    /** Characters that must never appear in a model-supplied command. */
    private val forbiddenChars = setOf(
        ';', '|', '&', '`', '$', '<', '>', '(', ')', '{', '}', '[', ']',
        '!', '*', '?', '~', '#', '\n', '\r', '\t'
    )
    private const val MAX_OUTPUT_CHARS = 4000
    private const val TIMEOUT_SECONDS = 10L

    /**
     * Wireless-debugging state the app can read: the system toggle
     * (`adb_wifi_enabled`, world-readable) and the adb TCP port when
     * the system exposes one. Wireless debugging uses a random TLS
     * port the system does not expose, so `adbTcpPort` is empty on a
     * wireless-only phone — that is expected, not an error.
     */
    @JvmStatic
    fun status(context: Context): Map<String, Any> {
        val resolver = context.contentResolver
        val wirelessOn = try {
            Settings.Global.getInt(resolver, "adb_wifi_enabled", 0) == 1
        } catch (_: Exception) {
            false
        }
        val adbOn = try {
            Settings.Global.getInt(resolver, "adb_enabled", 0) == 1
        } catch (_: Exception) {
            false
        }
        return mapOf(
            "wirelessDebugging" to wirelessOn,
            "adbEnabled" to adbOn,
            "adbTcpPort" to adbTcpPort(),
        )
    }

    private fun adbTcpPort(): String {
        return try {
            val process = ProcessBuilder("getprop", "service.adb.tcp.port")
                .redirectErrorStream(true)
                .start()
            val finished = process.waitFor(5, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                return ""
            }
            process.inputStream.bufferedReader().use { it.readLine() }
                ?.trim().orEmpty()
        } catch (_: Exception) {
            ""
        }
    }

    /**
     * Runs one read-only command as the app itself and returns
     * "exit=<code>\n<output>" (output truncated). Anything outside the
     * allowlist, any shell metacharacter, or a timeout comes back as an
     * "error: …" string. Never throws.
     */
    @JvmStatic
    fun runShell(command: String): String {
        val argv = parseCommand(command) ?: return "error: command not allowed — " +
            "only read-only commands (getprop, settings get, pm list, " +
            "dumpsys, logcat, ip, ps) may run, with no shell metacharacters"
        return try {
            val builder = ProcessBuilder(argv).redirectErrorStream(true)
            val process = builder.start()
            val output = StringBuilder()
            val readerThread = Thread {
                try {
                    val buffer = ByteArray(8192)
                    var read: Int
                    val stream = process.inputStream
                    while (stream.read(buffer).also { read = it } != -1) {
                        if (output.length < 65536) {
                            output.append(String(buffer, 0, read, Charsets.UTF_8))
                        }
                    }
                } catch (_: Exception) {
                    // Reader ends when the process dies; ignore.
                }
            }
            readerThread.start()
            val finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                readerThread.join(1000)
                return "error: command timed out after ${TIMEOUT_SECONDS}s"
            }
            readerThread.join(2000)
            val text = output.toString().trim().take(MAX_OUTPUT_CHARS)
            "exit=${process.exitValue()}\n$text"
        } catch (e: Exception) {
            "error: ${e.message ?: e.toString()}"
        }
    }

    /**
     * Splits the command into argv, or null when it is not allowed.
     * No shell is involved, so pipes, redirects and `&&` cannot run.
     * `settings` may only read (`settings get …`); `pm` may only list.
     * `logcat` always dumps and exits (`-d`).
     */
    private fun parseCommand(command: String): List<String>? {
        val trimmed = command.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_COMMAND_CHARS) return null
        if (trimmed.any { it in forbiddenChars }) return null
        val argv = trimmed.split(Regex("\\s+"))
        if (argv.isEmpty() || argv[0] !in allowedCommands) return null
        when (argv[0]) {
            "settings" -> if (argv.size < 2 || argv[1] != "get") return null
            "pm" -> if (argv.size < 2 || argv[1] != "list") return null
            "logcat" -> return argv + "-d"
        }
        return argv
    }

    /**
     * Commands the paired adb shell may run, as the shell user.
     * Same metacharacter rules as [parseCommand], but the wider set
     * the shell user needs: input (tap/keyevent/text), svc, cmd,
     * settings get/put, and am start. Anything not listed — rm,
     * reboot, su, keyguard changes — is refused by the allowlist.
     */
    @JvmStatic
    fun parseAdbCommand(command: String): List<String>? {
        val trimmed = command.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_COMMAND_CHARS) return null
        if (trimmed.any { it in forbiddenChars }) return null
        val argv = trimmed.split(Regex("\\s+"))
        if (argv.isEmpty()) return null
        val allowedAdb = setOf(
            "getprop", "settings", "pm", "dumpsys", "logcat", "ip", "ps",
            "input", "svc", "cmd", "am"
        )
        if (argv[0] !in allowedAdb) return null
        when (argv[0]) {
            "settings" -> if (argv.size < 2 || (argv[1] != "get" && argv[1] != "put")) return null
            "pm" -> if (argv.size < 2 || argv[1] != "list") return null
            "am" -> if (argv.size < 2 || argv[1] != "start") return null
            "logcat" -> return argv + "-d"
        }
        return argv
    }
}
