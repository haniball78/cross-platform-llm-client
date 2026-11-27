package com.orailnoor.privatelm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Twisted-Edwards arithmetic on Ed25519, written for the BoringSSL
 * `spake25519` construction (adb wireless pairing). Pure Java, no
 * Android APIs, so it can be unit-tested on a plain JVM.
 *
 * <p>Points are (x, y) affine pairs over p = 2^255 - 19 with
 * a = -1, d = -121665/121666. Encoding is the standard Ed25519
 * compressed form: y little-endian with the sign of x in the top bit.
 *
 * <p>Constants M and N are BoringSSL's SPAKE2 points, verified against
 * the comments in boringssl/src/crypto/curve25519/spake25519.cc:
 * M = 5ada7e4b…eed12e, N = 10e3df0a…c778.
 */
public final class Ed25519 {

    /** Field prime p = 2^255 - 19. */
    public static final BigInteger P =
            BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));

    /** Curve parameter d = -121665 / 121666 mod p. */
    public static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);

    /** Order of the prime-order subgroup. */
    public static final BigInteger L = BigInteger.valueOf(2).pow(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));

    /** sqrt(-1) mod p = 2^((p-1)/4) mod p. */
    private static final BigInteger SQRT_M1 =
            BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

    /** (p+3)/8, used by the p = 5 (mod 8) square-root ladder. */
    private static final BigInteger P_PLUS_3_DIV_8 =
            P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8));

    /** Base point, compressed (standard Ed25519 encoding). */
    public static final byte[] BASE_COMPRESSED = hexToBytes(
            "5866666666666666666666666666666666666666666666666666666666666666");

    /** BoringSSL SPAKE2 point M, compressed. */
    public static final byte[] M_COMPRESSED = hexToBytes(
            "5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e");

    /** BoringSSL SPAKE2 point N, compressed. */
    public static final byte[] N_COMPRESSED = hexToBytes(
            "10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778");

    /** One affine point on the curve. */
    public static final class Point {
        public final BigInteger x;
        public final BigInteger y;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        /** The identity point (0, 1). */
        public static Point identity() {
            return new Point(BigInteger.ZERO, BigInteger.ONE);
        }

        public Point negate() {
            return new Point(P.subtract(x).mod(P), y);
        }

        public boolean isOnCurve() {
            // -x^2 + y^2 = 1 + d*x^2*y^2  (a = -1)
            BigInteger xx = x.multiply(x).mod(P);
            BigInteger yy = y.multiply(y).mod(P);
            BigInteger left = yy.subtract(xx).mod(P);
            BigInteger right = BigInteger.ONE
                    .add(D.multiply(xx).multiply(yy)).mod(P);
            return left.equals(right);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Point)) return false;
            Point other = (Point) o;
            return x.equals(other.x) && y.equals(other.y);
        }

        @Override
        public int hashCode() {
            return x.hashCode() * 31 + y.hashCode();
        }
    }

    private Ed25519() {
    }

    /** Decodes a 32-byte compressed point; throws when not on the curve. */
    public static Point decode(byte[] encoded) {
        if (encoded == null || encoded.length != 32) {
            throw new IllegalArgumentException("compressed point must be 32 bytes");
        }
        byte[] copy = Arrays.copyOf(encoded, 32);
        boolean xOdd = (copy[31] & 0x80) != 0;
        copy[31] &= 0x7f;
        BigInteger y = leToBig(copy);
        if (y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("y out of range");
        }
        // x = sqrt((y^2 - 1) / (d*y^2 + 1)) mod p.
        BigInteger yy = y.multiply(y).mod(P);
        BigInteger u = yy.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(yy).add(BigInteger.ONE).mod(P);
        BigInteger t = u.multiply(v.modInverse(P)).mod(P);
        BigInteger x = t.modPow(P_PLUS_3_DIV_8, P);
        if (!x.multiply(x).mod(P).equals(t)) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        if (!x.multiply(x).mod(P).equals(t)) {
            throw new IllegalArgumentException("point is not on the curve");
        }
        if (x.testBit(0) != xOdd) {
            x = P.subtract(x);
        }
        Point point = new Point(x, y);
        if (!point.isOnCurve()) {
            throw new IllegalArgumentException("point is not on the curve");
        }
        return point;
    }

    /** Encodes a point in compressed form. */
    public static byte[] encode(Point point) {
        byte[] out = bigToLe(point.y, 32);
        if (point.x.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    /** Twisted-Edwards addition (a = -1). */
    public static Point add(Point a, Point b) {
        BigInteger x1 = a.x, y1 = a.y, x2 = b.x, y2 = b.y;
        BigInteger x1x2 = x1.multiply(x2).mod(P);
        BigInteger y1y2 = y1.multiply(y2).mod(P);
        BigInteger dTerm = D.multiply(x1x2).multiply(y1y2).mod(P);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).mod(P)
                .multiply(BigInteger.ONE.add(dTerm).modInverse(P)).mod(P);
        // a = -1, so y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
        //             = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2).
        BigInteger y3 = y1y2.add(x1x2).mod(P)
                .multiply(BigInteger.ONE.subtract(dTerm).modInverse(P)).mod(P);
        return new Point(x3, y3);
    }

    /** Scalar multiplication by a 32-byte little-endian scalar (reduced mod L). */
    public static Point scalarMult(byte[] scalarLe, Point point) {
        BigInteger k = leToBig(scalarLe).mod(L);
        Point result = Point.identity();
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            result = add(result, result);
            if (k.testBit(i)) {
                result = add(result, point);
            }
        }
        return result;
    }

    /** The base point, decoded. */
    public static Point base() {
        return decode(BASE_COMPRESSED);
    }

    /** BoringSSL SPAKE2 point M, decoded. */
    public static Point pointM() {
        return decode(M_COMPRESSED);
    }

    /** BoringSSL SPAKE2 point N, decoded. */
    public static Point pointN() {
        return decode(N_COMPRESSED);
    }

    /**
     * BoringSSL x25519_sc_reduce: a 64-byte little-endian integer
     * reduced mod L, returned as 32 little-endian bytes.
     */
    public static byte[] scReduce(byte[] wideLe) {
        if (wideLe == null || wideLe.length != 64) {
            throw new IllegalArgumentException("sc_reduce input must be 64 bytes");
        }
        return bigToLe(leToBig(wideLe).mod(L), 32);
    }

    /** SHA-512, for the SPAKE2 password hash. */
    public static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }

    /** Little-endian bytes to an unsigned BigInteger. */
    public static BigInteger leToBig(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    /** BigInteger to little-endian bytes of exactly {@code size}. */
    public static byte[] bigToLe(BigInteger value, int size) {
        byte[] be = value.toByteArray();
        byte[] out = new byte[size];
        // value.toByteArray is big-endian with a possible leading zero.
        int copyLen = Math.min(be.length, size);
        for (int i = 0; i < copyLen; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    /** Lowercase hex to bytes. */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    /** Bytes to lowercase hex. */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
