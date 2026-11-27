package com.orailnoor.privatelm;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * The adb connect path to the phone's own wireless-debugging daemon:
 * plaintext CNXN, the device answers A_STLS, TLS 1.3 with ALPN
 * "adb" (our client cert is the paired RSA key — no AUTH exchange
 * on the TLS path), CNXN again, then OPEN "shell,v2,raw:&lt;cmd&gt;"
 * with exit-code frames. Commands run as the shell user.
 */
public final class AdbConnection {

    private AdbConnection() {
    }

    /** One shell command over the paired connection. Returns "exit=&lt;code&gt;\n&lt;output&gt;". */
    public static String runShell(Context context, String host, int port,
                                  String command, int timeoutMs) throws Exception {
        KeyPair key = AdbPairing.getOrCreateKey(context);
        byte[] certDer = AdbKey.buildSelfSignedCert(key);
        SSLContext tls = AdbTls.newContext(key.getPrivate(), certDer);

        Socket plain = new Socket();
        plain.connect(new InetSocketAddress(host, port), 5000);
        plain.setSoTimeout(timeoutMs);
        try {
            OutputStream rawOut = plain.getOutputStream();
            InputStream rawIn = plain.getInputStream();
            rawOut.write(AdbWire.encode(AdbWire.CMD_CNXN, AdbWire.VERSION,
                    AdbWire.MAX_PAYLOAD, "host::shell_v2".getBytes(StandardCharsets.UTF_8)));
            rawOut.flush();
            AdbWire.Message first = AdbWire.read(rawIn);
            InputStream in;
            OutputStream out;
            SSLSocket tlsSocket = null;
            if (first.command == AdbWire.CMD_STLS) {
                tlsSocket = AdbTls.wrapSocket(tls, plain, host, port);
                in = tlsSocket.getInputStream();
                out = tlsSocket.getOutputStream();
            } else if (first.command == AdbWire.CMD_CNXN) {
                // Plaintext adbd (old tcpip mode): no TLS upgrade.
                in = rawIn;
                out = rawOut;
            } else {
                throw new IOException("unexpected first message: " + first.commandName());
            }
            try {
                return runShellOverStream(in, out, command, timeoutMs);
            } finally {
                if (tlsSocket != null) {
                    try {
                        tlsSocket.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        } finally {
            try {
                plain.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static String runShellOverStream(InputStream in, OutputStream out,
                                             String command, int timeoutMs) throws Exception {
        // CNXN over the (possibly TLS) transport.
        out.write(AdbWire.encode(AdbWire.CMD_CNXN, AdbWire.VERSION,
                AdbWire.MAX_PAYLOAD, "host::shell_v2".getBytes(StandardCharsets.UTF_8)));
        out.flush();
        AdbWire.Message banner = AdbWire.read(in);
        if (banner.command != AdbWire.CMD_CNXN) {
            throw new IOException("expected the device banner, got " + banner.commandName());
        }
        String bannerText = new String(banner.payload, StandardCharsets.UTF_8);
        boolean shellV2 = bannerText.contains("shell_v2");

        int localId = 1;
        String service = (shellV2 ? "shell,v2,raw:" : "shell:") + command;
        out.write(AdbWire.encode(AdbWire.CMD_OPEN, localId, 0,
                service.getBytes(StandardCharsets.UTF_8)));
        out.flush();
        AdbWire.Message okay = AdbWire.read(in);
        if (okay.command == AdbWire.CMD_CLSE) {
            throw new IOException("the phone refused the shell stream (key not authorised?)");
        }
        if (okay.command != AdbWire.CMD_OKAY || okay.arg1 != localId) {
            throw new IOException("expected OKAY for the shell stream, got " + okay.commandName());
        }
        int remoteId = okay.arg0;

        AdbWire.ShellV2Reader reader = new AdbWire.ShellV2Reader();
        StringBuilder legacyOut = new StringBuilder();
        long deadline = System.currentTimeMillis() + timeoutMs;
        try {
            while (true) {
                if (System.currentTimeMillis() > deadline) {
                    throw new SocketTimeoutException("shell command timed out");
                }
                AdbWire.Message msg = AdbWire.read(in);
                if (msg.command == AdbWire.CMD_WRTE) {
                    if (msg.arg1 != localId) continue;
                    out.write(AdbWire.encode(AdbWire.CMD_OKAY, remoteId, localId, null));
                    out.flush();
                    if (shellV2) {
                        reader.feed(msg.payload);
                    } else {
                        legacyOut.append(new String(msg.payload, StandardCharsets.UTF_8));
                    }
                    if (shellV2 && reader.exitCode() != null) {
                        // The exit frame arrived; adbd closes the stream next.
                        continue;
                    }
                } else if (msg.command == AdbWire.CMD_CLSE) {
                    break;
                } else if (msg.command == AdbWire.CMD_OKAY) {
                    // Flow-control ack; ignore.
                } else {
                    throw new IOException("unexpected message: " + msg.commandName());
                }
            }
        } catch (SocketTimeoutException e) {
            throw new IOException("shell command timed out after " + (timeoutMs / 1000) + "s", e);
        } finally {
            try {
                out.write(AdbWire.encode(AdbWire.CMD_CLSE, remoteId, localId, null));
                out.flush();
            } catch (Exception ignored) {
            }
        }

        int exit = shellV2
                ? (reader.exitCode() == null ? -1 : reader.exitCode())
                : 0;
        String stdout = shellV2 ? reader.stdout() : legacyOut.toString();
        String stderr = shellV2 ? reader.stderr() : "";
        StringBuilder result = new StringBuilder("exit=").append(exit).append('\n');
        result.append(stdout.trim());
        if (!stderr.trim().isEmpty()) {
            result.append("\n[stderr]\n").append(stderr.trim());
        }
        return result.toString().trim();
    }
}
