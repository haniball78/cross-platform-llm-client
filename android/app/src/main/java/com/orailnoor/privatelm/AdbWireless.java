package com.orailnoor.privatelm;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Facade for the chat model's wireless-debugging tool: status,
 * pairing, and shell commands over the full adb client.
 *
 * <p>When the phone is paired, shell commands run through the adb
 * connection as the shell user (30 s timeout). When it is not
 * paired, the tool falls back to the read-only on-device shell in
 * {@link WirelessDebug} — and says so in the result, so the model
 * never mistakes the fallback for shell-user power.
 */
public final class AdbWireless {

    private static final int SHELL_TIMEOUT_MS = 30_000;
    private static final int DISCOVERY_TIMEOUT_MS = 8000;
    private static final int MAX_OUTPUT_CHARS = 4000;

    private AdbWireless() {
    }

    /** Wireless-debugging status for the model, including pairing state. */
    public static Map<String, Object> status(Context context) {
        Map<String, Object> status = new HashMap<>(WirelessDebug.status(context));
        String guid = AdbPairing.storedGuid(context);
        status.put("paired", guid != null && !guid.isEmpty());
        status.put("guid", guid == null ? "" : guid);
        int port = context.getSharedPreferences(AdbPairing.PREFS, Context.MODE_PRIVATE)
                .getInt(AdbPairing.PREF_CONNECT_PORT, 0);
        status.put("connectPort", port);
        return status;
    }

    /** Pairs with the phone's own pairing port. Returns a readable result. */
    public static String pair(Context context, int port, String code) {
        try {
            return AdbPairing.pair(context, port, code);
        } catch (Exception e) {
            return "error: " + (e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    /** Forgets the pairing (the device keeps our key until it expires). */
    public static void unpair(Context context) {
        AdbPairing.clearPairing(context);
    }

    /** One shell command, through the adb connection when paired. */
    public static String shell(Context context, String command) {
        return shell(context, command, 0);
    }

    /**
     * One shell command, through the adb connection when paired.
     * {@code connectPortHint} is the connect port the user typed in
     * the Server view (0 = none); it is used when discovery cannot
     * find the port and no working port was saved yet.
     */
    public static String shell(Context context, String command, int connectPortHint) {
        if (WirelessDebug.parseAdbCommand(command) == null) {
            return "error: command not allowed — only these run, with no "
                    + "shell metacharacters: getprop, settings get/put, pm list, "
                    + "dumpsys, logcat, ip, ps, input, svc, cmd, am start";
        }
        if (!AdbPairing.isPaired(context)) {
            String out = WirelessDebug.runShell(command);
            return "not paired (read-only app shell — privileged commands fail):\n" + out;
        }
        try {
            Endpoint endpoint = resolveConnectEndpoint(context, connectPortHint);
            String out = AdbConnection.runShell(
                    context, endpoint.host, endpoint.port, command, SHELL_TIMEOUT_MS);
            context.getSharedPreferences(AdbPairing.PREFS, Context.MODE_PRIVATE)
                    .edit().putInt(AdbPairing.PREF_CONNECT_PORT, endpoint.port).apply();
            return out.length() > MAX_OUTPUT_CHARS
                    ? out.substring(0, MAX_OUTPUT_CHARS) + "\n[output truncated]"
                    : out;
        } catch (Exception e) {
            return "error: wireless shell could not connect ("
                    + (e.getMessage() == null ? e.toString() : e.getMessage())
                    + ") — pairing is still saved; if this keeps failing, "
                    + "re-pair from the Server view";
        }
    }

    /** Hosts the phone's own adbd may listen on: loopback first, then Wi-Fi IPs. */
    static List<String> candidateHosts(Context context) {
        List<String> hosts = new ArrayList<>();
        hosts.add("127.0.0.1");
        try {
            for (NetworkInterface iface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!iface.isUp() || iface.isLoopback()) continue;
                for (InetAddress addr : Collections.list(iface.getInetAddresses())) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        String host = addr.getHostAddress();
                        if (host != null && !hosts.contains(host)) hosts.add(host);
                    }
                }
            }
        } catch (Exception ignored) {
            // Loopback alone is enough to try.
        }
        return hosts;
    }

    /** One connect endpoint: host + port. */
    static final class Endpoint {
        final String host;
        final int port;

        Endpoint(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    /**
     * Finds the connect port: mDNS discovery of _adb-tls-connect._tcp
     * first, then the last port that worked, then the port the user
     * typed in the Server view. Throws when none of them knows it.
     */
    static Endpoint resolveConnectEndpoint(Context context, int connectPortHint) throws Exception {
        Endpoint discovered = discoverConnectService(context);
        if (discovered != null) return discovered;
        int savedPort = context.getSharedPreferences(AdbPairing.PREFS, Context.MODE_PRIVATE)
                .getInt(AdbPairing.PREF_CONNECT_PORT, 0);
        if (savedPort > 0) {
            return new Endpoint("127.0.0.1", savedPort);
        }
        if (connectPortHint > 0) {
            return new Endpoint("127.0.0.1", connectPortHint);
        }
        throw new IllegalStateException("no connect port known — open Developer options "
                + "→ Wireless debugging and enter the 'IP address & Port' shown there "
                + "in the Server view, or keep wireless debugging on so discovery can find it");
    }

    private static Endpoint discoverConnectService(Context context) {
        NsdManager nsd = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
        if (nsd == null) return null;
        WifiManager wifi = (WifiManager) context.getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
        WifiManager.MulticastLock lock = null;
        if (wifi != null) {
            try {
                lock = wifi.createMulticastLock("privatelm-adb-discovery");
                lock.setReferenceCounted(false);
                lock.acquire();
            } catch (Exception ignored) {
                lock = null;
            }
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Endpoint> found = new AtomicReference<>();
        NsdManager.ResolveListener resolveListener = new NsdManager.ResolveListener() {
            @Override
            public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
                latch.countDown();
            }

            @Override
            public void onServiceResolved(NsdServiceInfo serviceInfo) {
                InetAddress host = serviceInfo.getHost();
                if (host != null && serviceInfo.getPort() > 0) {
                    found.set(new Endpoint(host.getHostAddress(), serviceInfo.getPort()));
                }
                latch.countDown();
            }
        };
        NsdManager.DiscoveryListener discoveryListener = new NsdManager.DiscoveryListener() {
            @Override
            public void onDiscoveryStarted(String regType) {
            }

            @Override
            public void onServiceFound(NsdServiceInfo serviceInfo) {
                nsd.resolveService(serviceInfo, resolveListener);
            }

            @Override
            public void onServiceLost(NsdServiceInfo serviceInfo) {
            }

            @Override
            public void onDiscoveryStopped(String serviceType) {
            }

            @Override
            public void onStartDiscoveryFailed(String serviceType, int errorCode) {
                latch.countDown();
            }

            @Override
            public void onStopDiscoveryFailed(String serviceType, int errorCode) {
            }
        };
        try {
            nsd.discoverServices("_adb-tls-connect._tcp",
                    NsdManager.PROTOCOL_DNS_SD, discoveryListener);
            latch.await(DISCOVERY_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (Exception ignored) {
            // Discovery is best-effort; the saved port is the fallback.
        } finally {
            try {
                nsd.stopServiceDiscovery(discoveryListener);
            } catch (Exception ignored) {
            }
            if (lock != null) {
                try {
                    lock.release();
                } catch (Exception ignored) {
                }
            }
        }
        return found.get();
    }
}
