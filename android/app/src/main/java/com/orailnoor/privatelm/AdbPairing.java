package com.orailnoor.privatelm;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * Android 11+ wireless-debugging pairing, driven on the phone itself.
 *
 * <p>Flow (AOSP packages/modules/adb/pairing_connection +
 * pairing_auth): TCP to the pairing port, TLS 1.3 with ALPN "adb"
 * (server cert unverified, our self-signed cert presented), then
 * the SPAKE2 password is the 6-digit code bytes followed by 64
 * bytes of TLS exported keying material (label "adb-label" WITH
 * its trailing NUL — AOSP passes sizeof() as the label length).
 * SPAKE2 (BoringSSL spake25519) runs over 6-byte framed packets,
 * then the PeerInfo exchange (AES-128-GCM over an 8192-byte
 * PeerInfo: type 0 = our RSA public-key line, type 1 = the device
 * GUID we get back). Success enrolls our RSA key in the device's
 * /data/misc/adb/adb_keys.
 *
 * <p>The exporter label is tried with the NUL first and without it
 * second, because a wrong label produces a valid-looking exchange
 * whose PeerInfo tag simply never verifies — retrying the other
 * label is the only way to tell them apart without a device.
 */
public final class AdbPairing {

    static final String PREFS = "adb_wireless";
    static final String PREF_PRIVATE_PEM = "priv_pem";
    static final String PREF_GUID = "guid";
    static final String PREF_CONNECT_PORT = "connect_port";

    private static final int PEER_INFO_SIZE = 8192;
    private static final byte TYPE_SPAKE2_MSG = 0;
    private static final byte TYPE_PEER_INFO = 1;
    private static final byte PEER_TYPE_RSA_PUB_KEY = 0;
    private static final byte PEER_TYPE_GUID = 1;
    private static final int MAX_PAYLOAD = PEER_INFO_SIZE * 2;
    private static final int SOCKET_TIMEOUT_MS = 30_000;

    private AdbPairing() {
    }

    /** Our stored RSA identity, generated once and reused for every pairing. */
    static KeyPair getOrCreateKey(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String pem = prefs.getString(PREF_PRIVATE_PEM, null);
        if (pem != null && !pem.isEmpty()) {
            try {
                PrivateKey priv = AdbKey.privateKeyFromPem(pem);
                java.security.PublicKey pub = readPublicFromPrivate(priv);
                return new KeyPair(pub, priv);
            } catch (Exception ignored) {
                // Corrupt stored key: fall through and generate a new one.
            }
        }
        KeyPair fresh = AdbKey.generate();
        prefs.edit()
                .putString(PREF_PRIVATE_PEM, AdbKey.privateKeyToPem(fresh.getPrivate()))
                .apply();
        return fresh;
    }

    private static java.security.PublicKey readPublicFromPrivate(PrivateKey priv)
            throws Exception {
        java.security.KeyFactory factory = java.security.KeyFactory.getInstance("RSA");
        java.security.interfaces.RSAPrivateCrtKey crt =
                (java.security.interfaces.RSAPrivateCrtKey) priv;
        return factory.generatePublic(new java.security.spec.RSAPublicKeySpec(
                crt.getModulus(), crt.getPublicExponent()));
    }

    static String storedGuid(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(PREF_GUID, "");
    }

    static boolean isPaired(Context context) {
        String guid = storedGuid(context);
        return guid != null && !guid.isEmpty();
    }

    static void clearPairing(Context context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().remove(PREF_GUID).apply();
    }

    /**
     * Pairs with the phone's own wireless-debugging pairing port.
     * Returns a human-readable result; throws on failure.
     */
    public static String pair(Context context, int port, String code) throws Exception {
        if (code == null || !code.matches("\\d{6}")) {
            throw new IllegalArgumentException("Pairing code must be 6 digits.");
        }
        KeyPair key = getOrCreateKey(context);
        Exception lastError = null;
        for (String label : new String[]{"adb-label\u0000", "adb-label"}) {
            try {
                String guid = attempt(context, key, port, code, label);
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().putString(PREF_GUID, guid).apply();
                return "Paired with this phone (device GUID " + guid + "). "
                        + "The chat model can now run shell commands as the shell user.";
            } catch (Exception e) {
                lastError = e;
            }
        }
        throw new IOException("Pairing failed: "
                + (lastError == null ? "unknown error" : lastError.getMessage()), lastError);
    }

    private static String attempt(Context context, KeyPair key, int port,
                                  String code, String exporterLabel) throws Exception {
        byte[] certDer = AdbKey.buildSelfSignedCert(key);
        SSLContext tls = AdbTls.newContext(key.getPrivate(), certDer);
        Exception lastConnectError = null;
        for (String host : AdbWireless.candidateHosts(context)) {
            Socket plain = new Socket();
            try {
                plain.connect(new InetSocketAddress(host, port), 5000);
                plain.setSoTimeout(SOCKET_TIMEOUT_MS);
                SSLSocket socket = AdbTls.wrapSocket(tls, plain, host, port);
                try {
                    return exchangeOverTls(socket, key, code, exporterLabel);
                } finally {
                    try {
                        socket.close();
                    } catch (IOException ignored) {
                    }
                }
            } catch (IOException e) {
                lastConnectError = e;
                try {
                    plain.close();
                } catch (IOException ignored) {
                }
            }
        }
        throw new IOException("Could not reach the pairing port"
                + (lastConnectError == null ? "" : ": " + lastConnectError.getMessage()),
                lastConnectError);
    }

    private static String exchangeOverTls(SSLSocket socket, KeyPair key,
                                          String code, String exporterLabel) throws Exception {
        byte[] ekm = AdbTls.exportKeyingMaterial(socket, exporterLabel, 64);
        byte[] codeBytes = code.getBytes(StandardCharsets.UTF_8);
        byte[] password = new byte[codeBytes.length + ekm.length];
        System.arraycopy(codeBytes, 0, password, 0, codeBytes.length);
        System.arraycopy(ekm, 0, password, codeBytes.length, ekm.length);

        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        Spake25519 spake = Spake25519.aliceForPairing();
        byte[] myMsg = spake.generateMessage(password);
        writePacket(out, TYPE_SPAKE2_MSG, myMsg);
        Packet peer = readPacket(in);
        if (peer.type != TYPE_SPAKE2_MSG || peer.payload.length != 32) {
            throw new IOException("expected a 32-byte SPAKE2 message from the phone");
        }
        byte[] sharedKey = spake.processMessage(peer.payload);

        byte[] aesKey = AdbHkdf.pairingKey(sharedKey);
        byte[] ourPeerInfo = buildOurPeerInfo(key);
        byte[] ciphertext = AdbHkdf.aesGcmEncrypt(
                aesKey, AdbHkdf.nonceForCounter(0), ourPeerInfo);
        writePacket(out, TYPE_PEER_INFO, ciphertext);
        Packet peerInfo = readPacket(in);
        if (peerInfo.type != TYPE_PEER_INFO) {
            throw new IOException("expected the phone's PeerInfo back");
        }
        byte[] plain;
        try {
            plain = AdbHkdf.aesGcmDecrypt(
                    aesKey, AdbHkdf.nonceForCounter(0), peerInfo.payload);
        } catch (IllegalArgumentException e) {
            throw new IOException("Pairing failed: the phone rejected the exchange "
                    + "(wrong pairing code, or the code expired — open a fresh "
                    + "pairing sheet and try again)", e);
        }
        if (plain.length != PEER_INFO_SIZE || plain[0] != PEER_TYPE_GUID) {
            throw new IOException("unexpected PeerInfo from the phone");
        }
        int end = 1;
        while (end < plain.length && plain[end] != 0) end++;
        String guid = new String(plain, 1, end - 1, StandardCharsets.UTF_8).trim();
        if (guid.isEmpty()) {
            throw new IOException("the phone returned an empty device GUID");
        }
        return guid;
    }

    private static byte[] buildOurPeerInfo(KeyPair key) {
        byte[] line = AdbKey.publicKeyLine(key.getPublic(), AdbKey.KEY_NAME)
                .getBytes(StandardCharsets.US_ASCII);
        if (line.length > PEER_INFO_SIZE - 1) {
            throw new IllegalStateException("adb public key line is too long");
        }
        byte[] out = new byte[PEER_INFO_SIZE];
        out[0] = PEER_TYPE_RSA_PUB_KEY;
        System.arraycopy(line, 0, out, 1, line.length);
        return out;
    }

    /** One 6-byte framed pairing packet. */
    private static final class Packet {
        final byte type;
        final byte[] payload;

        Packet(byte type, byte[] payload) {
            this.type = type;
            this.payload = payload;
        }
    }

    private static void writePacket(OutputStream out, byte type, byte[] payload)
            throws IOException {
        byte[] header = new byte[6];
        header[0] = 1; // version
        header[1] = type;
        int size = payload.length;
        header[2] = (byte) ((size >> 24) & 0xff);
        header[3] = (byte) ((size >> 16) & 0xff);
        header[4] = (byte) ((size >> 8) & 0xff);
        header[5] = (byte) (size & 0xff);
        out.write(header);
        if (size > 0) out.write(payload);
        out.flush();
    }

    private static Packet readPacket(InputStream in) throws IOException {
        byte[] header = AdbWire.readFully(in, 6);
        if (header[0] != 1) {
            throw new IOException("unsupported pairing packet version " + header[0]);
        }
        byte type = header[1];
        int size = ((header[2] & 0xff) << 24) | ((header[3] & 0xff) << 16)
                | ((header[4] & 0xff) << 8) | (header[5] & 0xff);
        if (size < 0 || size > MAX_PAYLOAD) {
            throw new IOException("pairing payload size out of range: " + size);
        }
        byte[] payload = size == 0 ? new byte[0] : AdbWire.readFully(in, size);
        return new Packet(type, payload);
    }
}
