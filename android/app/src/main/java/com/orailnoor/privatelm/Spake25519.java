package com.orailnoor.privatelm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * BoringSSL `spake25519` SPAKE2, as used by adb wireless pairing.
 * Ported from the algorithm in boringssl/src/crypto/curve25519/
 * spake25519.cc (Apache-2.0) — read, not copied: the structure and
 * constants below follow that file exactly, including its
 * "password scalar hack", which the adb side also uses (it is on by
 * default in BoringSSL and AOSP never disables it).
 *
 * <p>Transcript: SHA-512 over 8-byte little-endian length-prefixed
 * fields — my_name, their_name, my_msg, their_msg,
 * Diffie-Hellman shared point (encoded), password hash (the FULL
 * 64-byte SHA-512 of the password; {@code password_hash} is a
 * 64-byte field in BoringSSL's spake2_ctx_st). Alice orders the
 * names/messages my-first; Bob orders them their-first. The output
 * key is the full 64-byte SHA-512 digest.
 *
 * <p>For adb pairing the client is Alice with
 * my_name = "adb pair client\0", their_name = "adb pair server\0",
 * and the password is the 6-digit pairing code bytes followed by
 * the 64 bytes of TLS exported keying material.
 */
public final class Spake25519 {

    public enum Role { ALICE, BOB }

    private final Role role;
    private final byte[] myName;
    private final byte[] theirName;

    private byte[] privateKey;      // 32 bytes, reduced scalar, times 8
    private byte[] passwordScalar;  // 32 bytes, with the BoringSSL hack
    private byte[] passwordHash;    // 64 bytes, full SHA-512(password)
    private byte[] myMsg;           // 32 bytes, encoded masked point

    public Spake25519(Role role, byte[] myName, byte[] theirName) {
        this.role = role;
        this.myName = Arrays.copyOf(myName, myName.length);
        this.theirName = Arrays.copyOf(theirName, theirName.length);
    }

    /** Alice side of an adb pairing exchange. */
    public static Spake25519 aliceForPairing() {
        return new Spake25519(Role.ALICE,
                "adb pair client\u0000".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "adb pair server\u0000".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Generates our 32-byte SPAKE2 message for {@code password}.
     * Mirrors SPAKE2_generate_msg.
     */
    public byte[] generateMessage(byte[] password) {
        byte[] privateTmp = new byte[64];
        new SecureRandom().nextBytes(privateTmp);
        return generateMessage(password, privateTmp);
    }

    /**
     * Same as {@link #generateMessage(byte[])}, but with a caller
     * supplied 64-byte private seed — used by tests so the exchange
     * is deterministic and can be checked against an independent
     * implementation.
     */
    public byte[] generateMessage(byte[] password, byte[] privateSeed64) {
        if (privateSeed64 == null || privateSeed64.length != 64) {
            throw new IllegalArgumentException("private seed must be 64 bytes");
        }
        byte[] privateTmp = Arrays.copyOf(privateSeed64, 64);
        // x = sc_reduce(seed), then times the cofactor 8.
        byte[] reduced = Ed25519.scReduce(privateTmp);
        BigInteger x = Ed25519.leToBig(reduced).shiftLeft(3);
        privateKey = Ed25519.bigToLe(x, 32);

        Ed25519.Point p = Ed25519.scalarMult(privateKey, Ed25519.base());

        // mask = h(password) * <M or N>.
        byte[] passwordTmp = Ed25519.sha512(password);
        passwordHash = Arrays.copyOf(passwordTmp, 64);
        byte[] scalar = Ed25519.scReduce(passwordTmp);
        BigInteger w = Ed25519.leToBig(scalar);
        // The BoringSSL password-scalar hack (on by default): make the
        // low three bits zero by adding multiples of the group order.
        // Adding L flips bit 0, adding 2L flips bit 1, adding 4L flips
        // bit 2; each check reads the value after the previous addition.
        if (w.testBit(0)) w = w.add(Ed25519.L);
        if (w.testBit(1)) w = w.add(Ed25519.L.shiftLeft(1));
        if (w.testBit(2)) w = w.add(Ed25519.L.shiftLeft(2));
        passwordScalar = Ed25519.bigToLe(w, 32);

        Ed25519.Point maskPoint = role == Role.ALICE
                ? Ed25519.pointM() : Ed25519.pointN();
        Ed25519.Point mask = Ed25519.scalarMult(passwordScalar, maskPoint);
        Ed25519.Point masked = Ed25519.add(p, mask);
        myMsg = Ed25519.encode(masked);
        return Arrays.copyOf(myMsg, 32);
    }

    /**
     * Processes the peer's 32-byte SPAKE2 message and returns the
     * 64-byte shared key. Mirrors SPAKE2_process_msg.
     */
    public byte[] processMessage(byte[] theirMsg) {
        if (myMsg == null || theirMsg == null || theirMsg.length != 32) {
            throw new IllegalStateException("generate a message first, then feed a 32-byte peer message");
        }
        Ed25519.Point qStar = Ed25519.decode(theirMsg);

        // Unmask the peer's value with the peer's mask point.
        Ed25519.Point peerMaskPoint = role == Role.ALICE
                ? Ed25519.pointN() : Ed25519.pointM();
        Ed25519.Point peerMask = Ed25519.scalarMult(passwordScalar, peerMaskPoint);
        Ed25519.Point q = Ed25519.add(qStar, peerMask.negate());

        Ed25519.Point dhShared = Ed25519.scalarMult(privateKey, q);
        byte[] dhEncoded = Ed25519.encode(dhShared);

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            if (role == Role.ALICE) {
                updateWithLengthPrefix(sha, myName);
                updateWithLengthPrefix(sha, theirName);
                updateWithLengthPrefix(sha, myMsg);
                updateWithLengthPrefix(sha, theirMsg);
            } else {
                updateWithLengthPrefix(sha, theirName);
                updateWithLengthPrefix(sha, myName);
                updateWithLengthPrefix(sha, theirMsg);
                updateWithLengthPrefix(sha, myMsg);
            }
            updateWithLengthPrefix(sha, dhEncoded);
            updateWithLengthPrefix(sha, passwordHash);
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }

    /** Length-prefixes a field with its 8-byte little-endian length. */
    private static void updateWithLengthPrefix(MessageDigest sha, byte[] data) {
        byte[] lenLe = new byte[8];
        long len = data.length;
        for (int i = 0; i < 8; i++) {
            lenLe[i] = (byte) (len & 0xff);
            len >>= 8;
        }
        sha.update(lenLe);
        sha.update(data);
    }
}
