package com.orailnoor.privatelm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

/**
 * The adb RSA identity: key generation, PEM storage, the mincrypt
 * {@code adbkey.pub} line adbd enrolls, and a hand-built DER
 * self-signed X.509 certificate for the TLS client authentication.
 *
 * <p>No new dependencies: the certificate is built byte by byte
 * (DER), because Android has no public API to mint X.509 certs.
 * The mincrypt public-key blob is the 524-byte little-endian struct
 * adbd expects: len (64 words), n0inv, n[64] (modulus, least
 * significant word first), rr[64] (R^2 mod n, R = 2^2048), exponent.
 */
public final class AdbKey {

    public static final String KEY_NAME = "privatelm@android";

    private AdbKey() {
    }

    /** Generates a fresh RSA-2048 key pair (exponent 65537). */
    public static KeyPair generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048, new SecureRandom());
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    /** PKCS#8 private key as a PEM block. */
    public static String privateKeyToPem(PrivateKey privateKey) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n";
    }

    /** Parses a PKCS#8 PEM block back into a private key. */
    public static PrivateKey privateKeyFromPem(String pem) {
        try {
            String cleaned = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(cleaned);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid adb private key PEM", e);
        }
    }

    /**
     * The one-line {@code adbkey.pub} form adbd stores in
     * /data/misc/adb/adb_keys: base64(524-byte mincrypt struct) +
     * " " + name. No trailing newline.
     */
    public static String publicKeyLine(PublicKey publicKey, String name) {
        RSAPublicKey rsa = (RSAPublicKey) publicKey;
        BigInteger n = rsa.getModulus();
        BigInteger e = rsa.getPublicExponent();
        byte[] blob = new byte[524];
        putIntLe(blob, 0, 64); // len, in 32-bit words
        // n0inv = 0 - modInverse(n mod 2^32, 2^32), mod 2^32.
        BigInteger two32 = BigInteger.valueOf(2).pow(32);
        BigInteger n0 = n.mod(two32);
        BigInteger n0inv = two32.subtract(n0.modInverse(two32)).mod(two32);
        putIntLe(blob, 4, n0inv.intValue());
        // n[64]: modulus, least significant word first.
        for (int i = 0; i < 64; i++) {
            int word = n.shiftRight(32 * i)
                    .and(BigInteger.valueOf(0xffffffffL)).intValue();
            putIntLe(blob, 8 + 4 * i, word);
        }
        // rr[64]: R^2 mod n, R = 2^2048.
        BigInteger rr = BigInteger.valueOf(2).pow(2048)
                .modPow(BigInteger.valueOf(2), n);
        for (int i = 0; i < 64; i++) {
            int word = rr.shiftRight(32 * i)
                    .and(BigInteger.valueOf(0xffffffffL)).intValue();
            putIntLe(blob, 264 + 4 * i, word);
        }
        putIntLe(blob, 520, e.intValue());
        return Base64.getEncoder().encodeToString(blob) + " " + name;
    }

    private static void putIntLe(byte[] buf, int offset, int value) {
        buf[offset] = (byte) (value & 0xff);
        buf[offset + 1] = (byte) ((value >> 8) & 0xff);
        buf[offset + 2] = (byte) ((value >> 16) & 0xff);
        buf[offset + 3] = (byte) ((value >> 24) & 0xff);
    }

    /**
     * Builds a minimal self-signed X.509 v3 certificate (DER) for the
     * RSA key, signed with SHA256withRSA. Subject/issuer CN is "adb".
     * Validity: yesterday through +10 years.
     */
    public static byte[] buildSelfSignedCert(KeyPair keyPair) {
        try {
            long now = System.currentTimeMillis();
            long notBefore = now - 24L * 60 * 60 * 1000;
            long notAfter = now + 10L * 365 * 24 * 60 * 60 * 1000;

            RSAPublicKey rsa = (RSAPublicKey) keyPair.getPublic();
            byte[] rsaPubDer = derSequence(
                    derInteger(rsa.getModulus()),
                    derInteger(rsa.getPublicExponent()));
            byte[] spki = derSequence(
                    derSequence(derOid("1.2.840.113549.1.1.1"), derNull()),
                    derBitString(rsaPubDer));

            byte[] name = derSequence(derSet(derSequence(
                    derOid("2.5.4.3"),
                    derUtf8String("adb"))));

            byte[] sigAlg = derSequence(
                    derOid("1.2.840.113549.1.1.11"), derNull());

            byte[] tbs = derSequence(
                    derExplicit(0, derInteger(BigInteger.valueOf(2))),
                    derInteger(BigInteger.ONE),
                    sigAlg,
                    name,
                    derSequence(derUtcTime(notBefore), derUtcTime(notAfter)),
                    name,
                    spki);

            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(tbs);
            byte[] signature = signer.sign();

            byte[] cert = derSequence(tbs, sigAlg, derBitString(signature));
            // Prove the DER parses as a real certificate before returning it.
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate parsed = factory.generateCertificate(
                    new ByteArrayInputStream(cert));
            parsed.getPublicKey();
            return cert;
        } catch (Exception e) {
            throw new IllegalStateException("self-signed cert build failed", e);
        }
    }

    /** KeyManagers presenting our key + self-signed cert for TLS client auth. */
    public static KeyManager[] keyManagers(PrivateKey privateKey, byte[] certDer) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate cert = factory.generateCertificate(
                    new ByteArrayInputStream(certDer));
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            store.setKeyEntry("adb", privateKey,
                    "adb".toCharArray(), new Certificate[]{cert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(store, "adb".toCharArray());
            return kmf.getKeyManagers();
        } catch (Exception e) {
            throw new IllegalStateException("TLS key managers failed", e);
        }
    }

    // Minimal DER writer (plain ASCII section dividers only).

    private static byte[] derLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        }
        int bytes = 0;
        int tmp = length;
        while (tmp > 0) {
            bytes++;
            tmp >>= 8;
        }
        byte[] out = new byte[1 + bytes];
        out[0] = (byte) (0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out[1 + i] = (byte) (length & 0xff);
            length >>= 8;
        }
        return out;
    }

    private static byte[] derTlv(int tag, byte[] content) {
        byte[] len = derLength(content.length);
        byte[] out = new byte[1 + len.length + content.length];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, content.length);
        return out;
    }

    private static byte[] derSequence(byte[]... parts) {
        return derTlv(0x30, concat(parts));
    }

    private static byte[] derSet(byte[]... parts) {
        return derTlv(0x31, concat(parts));
    }

    private static byte[] derExplicit(int number, byte[] inner) {
        return derTlv(0xa0 + number, inner);
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return derTlv(0x02, bytes);
    }

    private static byte[] derOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            long v = Long.parseLong(parts[i]);
            // Base-128, most significant group first.
            int groups = 1;
            long t = v;
            while (t >= 128) {
                groups++;
                t >>= 7;
            }
            for (int g = groups - 1; g >= 0; g--) {
                int b = (int) ((v >> (7 * g)) & 0x7f);
                if (g > 0) b |= 0x80;
                out.write(b);
            }
        }
        return derTlv(0x06, out.toByteArray());
    }

    private static byte[] derNull() {
        return new byte[]{0x05, 0x00};
    }

    private static byte[] derUtf8String(String value) {
        return derTlv(0x0c, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static byte[] derBitString(byte[] content) {
        byte[] withUnusedBits = new byte[content.length + 1];
        withUnusedBits[0] = 0;
        System.arraycopy(content, 0, withUnusedBits, 1, content.length);
        return derTlv(0x03, withUnusedBits);
    }

    private static byte[] derUtcTime(long millis) {
        java.text.SimpleDateFormat fmt =
                new java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US);
        fmt.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        String text = fmt.format(new java.util.Date(millis));
        return derTlv(0x17, text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static byte[] concat(byte[][] parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
