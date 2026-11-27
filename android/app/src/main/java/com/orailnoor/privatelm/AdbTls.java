package com.orailnoor.privatelm;

import android.net.ssl.SSLSockets;
import android.os.Build;

import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * TLS 1.3 for the adb pairing/connect sockets: client certificate
 * authentication with our self-signed cert, the server certificate
 * explicitly unverified (adbd presents a self-signed cert), ALPN
 * "adb", and RFC 5705 exported keying material for the pairing
 * password.
 *
 * <p>ALPN and key export need API 29+; the app's minSdk is 28, so
 * both are guarded and fail plainly on older Android. The target
 * phone runs Android 16.
 */
public final class AdbTls {

    private AdbTls() {
    }

    /** Trust manager that accepts any server certificate (adbd is self-signed). */
    private static final TrustManager[] TRUST_ALL = new TrustManager[]{
        new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }
    };

    /** TLS context presenting our adb key + self-signed cert. */
    public static SSLContext newContext(PrivateKey privateKey, byte[] certDer) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(AdbKey.keyManagers(privateKey, certDer), TRUST_ALL, null);
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("TLS context failed", e);
        }
    }

    /**
     * Upgrades a connected plain socket to TLS 1.3 with ALPN "adb"
     * and starts the handshake.
     */
    public static SSLSocket wrapSocket(SSLContext ctx, Socket plain, String host, int port) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            throw new IllegalStateException(
                    "Wireless debugging needs Android 10+ (ALPN + key export)");
        }
        try {
            SSLSocket socket = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(plain, host, port, true);
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            SSLParameters params = socket.getSSLParameters();
            params.setApplicationProtocols(new String[]{"adb"});
            socket.setSSLParameters(params);
            socket.startHandshake();
            return socket;
        } catch (Exception e) {
            throw new IllegalStateException("TLS handshake failed: " + e.getMessage(), e);
        }
    }

    /**
     * RFC 5705 exported keying material (64 bytes for adb pairing).
     * The label must be passed exactly as AOSP does: "adb-label"
     * WITH its trailing NUL byte — AOSP passes sizeof() as the label
     * length, so the device exports with the 10-byte label.
     */
    public static byte[] exportKeyingMaterial(SSLSocket socket, String label, int length) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            throw new IllegalStateException(
                    "Wireless debugging needs Android 10+ (ALPN + key export)");
        }
        try {
            return SSLSockets.exportKeyingMaterial(socket, label, null, length);
        } catch (Exception e) {
            throw new IllegalStateException("key export failed: " + e.getMessage(), e);
        }
    }
}
