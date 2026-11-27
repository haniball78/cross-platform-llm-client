package com.orailnoor.privatelm;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869) and AES-128-GCM, for the adb pairing
 * PeerInfo exchange. Pure Java, no Android APIs.
 *
 * <p>adb pairing derives the PeerInfo key as
 * HKDF-SHA256(IKM = SPAKE2 shared key, salt = empty, info =
 * "adb pairing_auth aes-128-gcm key", L = 16). The 12-byte GCM
 * nonce holds a little-endian per-direction counter in its first
 * 8 bytes; both sides start at zero.
 */
public final class AdbHkdf {

    public static final String PAIRING_INFO = "adb pairing_auth aes-128-gcm key";
    public static final int KEY_BYTES = 16;
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BITS = 128;

    private AdbHkdf() {
    }

    /** HKDF-SHA256 extract + expand. Salt may be null (zeros). */
    public static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] realSalt = (salt == null || salt.length == 0)
                    ? new byte[32] : salt;
            mac.init(new SecretKeySpec(realSalt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            // Expand.
            Mac expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int filled = 0;
            byte counter = 1;
            while (filled < length) {
                expand.reset();
                expand.update(t);
                expand.update(info);
                expand.update(counter);
                t = expand.doFinal();
                int take = Math.min(t.length, length - filled);
                System.arraycopy(t, 0, out, filled, take);
                filled += take;
                counter++;
            }
            return out;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HKDF-SHA256 unavailable", e);
        }
    }

    /** The adb pairing PeerInfo key from a SPAKE2 shared key. */
    public static byte[] pairingKey(byte[] spakeSharedKey) {
        return hkdfSha256(null, spakeSharedKey,
                PAIRING_INFO.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                KEY_BYTES);
    }

    /** 12-byte GCM nonce: little-endian counter in the first 8 bytes. */
    public static byte[] nonceForCounter(long counter) {
        byte[] nonce = new byte[NONCE_BYTES];
        for (int i = 0; i < 8; i++) {
            nonce[i] = (byte) (counter & 0xff);
            counter >>= 8;
        }
        return nonce;
    }

    /** AES-128-GCM encrypt; returns ciphertext with the 16-byte tag appended. */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    /** AES-128-GCM decrypt; throws when the tag does not verify. */
    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(ciphertext);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException
                | NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES-GCM decrypt failed", e);
        } catch (Exception e) {
            // BadPaddingException / AEADBadTagException: wrong key or data.
            throw new IllegalArgumentException("AES-GCM tag verification failed", e);
        }
    }
}
