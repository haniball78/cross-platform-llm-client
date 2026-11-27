package com.orailnoor.privatelm

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import com.flyfishxu.kadb.Kadb
import com.flyfishxu.kadb.cert.KadbCert
import com.flyfishxu.kadb.shell.AdbShellResponse
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Facade for the chat model's wireless-debugging tool: status,
 * pairing, and shell commands over the Kadb adb client
 * (com.flyfishxu:kadb-android), the same library DroidDeck pairs
 * with. Kadb owns the pairing handshake and the shell transport;
 * this file only owns the app-side policy: loopback-only endpoints,
 * the allowlist fallback, and the result strings the model sees.
 *
 * <p>When the phone is paired, shell commands run through the adb
 * connection as the shell user (30 s timeout). When it is not
 * paired, the tool falls back to the read-only on-device shell in
 * [WirelessDebug] — and says so in the result, so the model
 * never mistakes the fallback for shell-user power.
 */
object AdbWireless {

    private const val PREFS = "adb_wireless"
    private const val PREF_PAIRED = "paired"
    private const val PREF_GUID = "guid"
    private const val PREF_CONNECT_PORT = "connect_port"

    private const val CERT_FILE = "wireless-adb-cert.pem"
    private const val KEY_FILE = "wireless-adb-key.pem"

    /** The phone's own wireless-debugging daemon, reached on loopback only. */
    private const val LOOPBACK = "127.0.0.1"

    private const val SHELL_TIMEOUT_MS = 30_000
    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val DISCOVERY_TIMEOUT_MS = 8000
    private const val MAX_OUTPUT_CHARS = 4000

    /** Wireless-debugging status for the model, including pairing state. */
    @JvmStatic
    fun status(context: Context): Map<String, Any> {
        val status = HashMap<String, Any>(WirelessDebug.status(context))
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        status["paired"] = prefs.getBoolean(PREF_PAIRED, false)
        status["guid"] = prefs.getString(PREF_GUID, "") ?: ""
        status["connectPort"] = prefs.getInt(PREF_CONNECT_PORT, 0)
        return status
    }

    /** Pairs with the phone's own pairing port. Returns a readable result. */
    @JvmStatic
    fun pair(context: Context, port: Int, code: String): String {
        if (code.isEmpty() || !code.matches(Regex("\\d{6}"))) {
            return "error: Pairing code must be 6 digits."
        }
        return try {
            loadOrCreateIdentity(context.applicationContext)
            runBlocking { Kadb.pair(LOOPBACK, port, code, "PrivateLM") }
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(PREF_PAIRED, true)
                .putString(PREF_GUID, "")
                .apply()
            "Paired with this phone. " +
                "The chat model can now run shell commands as the shell user."
        } catch (e: Exception) {
            "error: " + (e.message ?: e.toString())
        }
    }

    /** Forgets the pairing (the identity key files are kept, so re-pairing reuses them). */
    @JvmStatic
    fun unpair(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .remove(PREF_GUID)
            .remove(PREF_PAIRED)
            .remove(PREF_CONNECT_PORT)
            .apply()
    }

    /** One shell command, through the adb connection when paired. */
    @JvmStatic
    fun shell(context: Context, command: String): String {
        return shell(context, command, 0)
    }

    /**
     * One shell command, through the adb connection when paired.
     * [connectPortHint] is the connect port the user typed in
     * the Server view (0 = none); it is used when discovery cannot
     * find the port and no working port was saved yet.
     */
    @JvmStatic
    fun shell(context: Context, command: String, connectPortHint: Int): String {
        if (WirelessDebug.parseAdbCommand(command) == null) {
            return "error: command not allowed — only these run, with no " +
                "shell metacharacters: getprop, settings get/put, pm list, " +
                "dumpsys, logcat, ip, ps, input, svc, cmd, am start"
        }
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(PREF_PAIRED, false)) {
            val out = WirelessDebug.runShell(command)
            return "not paired (read-only app shell — privileged commands fail):\n$out"
        }
        return try {
            loadOrCreateIdentity(context.applicationContext)
            val port = resolveConnectEndpoint(context, connectPortHint)
            val response = Kadb.create(LOOPBACK, port, CONNECT_TIMEOUT_MS, SHELL_TIMEOUT_MS)
                .use { adb -> adb.shell(command) }
            prefs.edit().putInt(PREF_CONNECT_PORT, port).apply()
            val out = formatShellResult(response)
            if (out.length > MAX_OUTPUT_CHARS) {
                out.substring(0, MAX_OUTPUT_CHARS) + "\n[output truncated]"
            } else {
                out
            }
        } catch (e: Exception) {
            "error: wireless shell could not connect (" +
                (e.message ?: e.toString()) +
                ") — pairing is still saved; if this keeps failing, " +
                "re-pair from the Server view"
        }
    }

    /**
     * Our RSA identity for Kadb, loaded from the PEM files in
     * noBackupFilesDir or created once and saved there — the same
     * pattern DroidDeck uses. Kadb.pair and Kadb.create read the
     * identity from [KadbCert], so this must run before either.
     */
    @Synchronized
    private fun loadOrCreateIdentity(context: Context) {
        val directory = context.noBackupFilesDir
        val cert = File(directory, CERT_FILE)
        val key = File(directory, KEY_FILE)
        if (cert.isFile && key.isFile) {
            KadbCert.set(cert.readBytes(), key.readBytes())
            return
        }
        val identity = KadbCert.get(
            notAfter = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(3650)
        )
        KadbCert.set(identity.first, identity.second)
        writeAtomically(cert, identity.first)
        writeAtomically(key, identity.second)
    }

    private fun writeAtomically(destination: File, contents: ByteArray) {
        val temporary = File(destination.parentFile, "${destination.name}.tmp")
        temporary.writeBytes(contents)
        check(temporary.renameTo(destination)) { "Could not save the wireless identity" }
    }

    /** "exit=<code>\n<output>", plus a stderr section when there is one. */
    private fun formatShellResult(response: AdbShellResponse): String {
        val stdout = response.output.trim()
        val stderr = response.errorOutput.trim()
        val result = StringBuilder("exit=").append(response.exitCode).append('\n')
        result.append(stdout)
        if (stderr.isNotEmpty()) {
            result.append("\n[stderr]\n").append(stderr)
        }
        return result.toString().trim()
    }

    /**
     * Finds the connect port: mDNS discovery of _adb-tls-connect._tcp
     * first, then the last port that worked, then the port the user
     * typed in the Server view. The host is always loopback:
     * discovery only supplies the port. Throws when none of them
     * knows it.
     */
    private fun resolveConnectEndpoint(context: Context, connectPortHint: Int): Int {
        val discovered = discoverConnectPort(context)
        if (discovered != null) return discovered
        val savedPort = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(PREF_CONNECT_PORT, 0)
        if (savedPort > 0) return savedPort
        if (connectPortHint > 0) return connectPortHint
        throw IllegalStateException("no connect port known — open Developer options " +
            "→ Wireless debugging and enter the 'IP address & Port' shown there " +
            "in the Server view, or keep wireless debugging on so discovery can find it")
    }

    private fun discoverConnectPort(context: Context): Int? {
        val nsd = context.getSystemService(Context.NSD_SERVICE) as? NsdManager ?: return null
        val wifi = context.applicationContext
            .getSystemService(Context.WIFI_SERVICE) as? WifiManager
        var lock: WifiManager.MulticastLock? = null
        if (wifi != null) {
            try {
                lock = wifi.createMulticastLock("privatelm-adb-discovery")
                lock.setReferenceCounted(false)
                lock.acquire()
            } catch (_: Exception) {
                lock = null
            }
        }
        val latch = CountDownLatch(1)
        val found = AtomicReference<Int?>(null)
        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                latch.countDown()
            }

            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                if (serviceInfo.port > 0) {
                    found.set(serviceInfo.port)
                }
                latch.countDown()
            }
        }
        val discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {}
            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                nsd.resolveService(serviceInfo, resolveListener)
            }
            override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                latch.countDown()
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
        }
        try {
            nsd.discoverServices(
                "_adb-tls-connect._tcp",
                NsdManager.PROTOCOL_DNS_SD,
                discoveryListener
            )
            latch.await(DISCOVERY_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
            // Discovery is best-effort; the saved port is the fallback.
        } finally {
            try {
                nsd.stopServiceDiscovery(discoveryListener)
            } catch (_: Exception) {
            }
            if (lock != null) {
                try {
                    lock.release()
                } catch (_: Exception) {
                }
            }
        }
        return found.get()
    }
}
