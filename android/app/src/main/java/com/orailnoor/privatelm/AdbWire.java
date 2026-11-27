package com.orailnoor.privatelm;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * The adb wire protocol (AOSP protocol.txt / adb.h): 24-byte
 * little-endian message headers, and the shell-v2 frame format.
 * Pure Java, no Android APIs.
 *
 * <p>With protocol version 0x01000001 the sender writes
 * {@code data_check = 0} and the receiver skips checksum
 * verification. Magic is always {@code command ^ 0xFFFFFFFF}.
 */
public final class AdbWire {

    public static final int VERSION = 0x01000001;
    public static final int MAX_PAYLOAD = 4096;

    public static final int CMD_CNXN = 0x4E584E43; // "CNXN"
    public static final int CMD_AUTH = 0x48545541; // "AUTH"
    public static final int CMD_OPEN = 0x4E45504F; // "OPEN"
    public static final int CMD_OKAY = 0x59414B4F; // "OKAY"
    public static final int CMD_CLSE = 0x45534C43; // "CLSE"
    public static final int CMD_WRTE = 0x45545257; // "WRTE"
    public static final int CMD_STLS = 0x534C5453; // "STLS"

    public static final int HEADER_SIZE = 24;

    private AdbWire() {
    }

    /** One decoded adb message. */
    public static final class Message {
        public final int command;
        public final int arg0;
        public final int arg1;
        public final byte[] payload;

        public Message(int command, int arg0, int arg1, byte[] payload) {
            this.command = command;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.payload = payload;
        }

        public String commandName() {
            switch (command) {
                case CMD_CNXN: return "CNXN";
                case CMD_AUTH: return "AUTH";
                case CMD_OPEN: return "OPEN";
                case CMD_OKAY: return "OKAY";
                case CMD_CLSE: return "CLSE";
                case CMD_WRTE: return "WRTE";
                case CMD_STLS: return "STLS";
                default: return String.format("0x%08X", command);
            }
        }
    }

    /** Encodes one adb message: 24-byte header + payload. */
    public static byte[] encode(int command, int arg0, int arg1, byte[] payload) {
        byte[] data = payload == null ? new byte[0] : payload;
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + data.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(command);
        buf.putInt(arg0);
        buf.putInt(arg1);
        buf.putInt(data.length);
        buf.putInt(0); // data_check: 0 for protocol 0x01000001
        buf.putInt(command ^ 0xFFFFFFFF);
        buf.put(data);
        return buf.array();
    }

    /** Reads and validates one adb message from a stream. */
    public static Message read(InputStream in) throws IOException {
        byte[] header = readFully(in, HEADER_SIZE);
        ByteBuffer buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        int command = buf.getInt();
        int arg0 = buf.getInt();
        int arg1 = buf.getInt();
        int dataLength = buf.getInt();
        buf.getInt(); // data_check, skipped for 0x01000001
        int magic = buf.getInt();
        if (magic != (command ^ 0xFFFFFFFF)) {
            throw new IOException("bad adb magic for " + String.format("0x%08X", command));
        }
        if (dataLength < 0 || dataLength > 1024 * 1024) {
            throw new IOException("bad adb payload length " + dataLength);
        }
        byte[] payload = dataLength == 0 ? new byte[0] : readFully(in, dataLength);
        return new Message(command, arg0, arg1, payload);
    }

    /** Reads exactly {@code size} bytes or throws EOFException. */
    public static byte[] readFully(InputStream in, int size) throws IOException {
        byte[] buf = new byte[size];
        int read = 0;
        while (read < size) {
            int n = in.read(buf, read, size - read);
            if (n < 0) {
                throw new EOFException("EOF after " + read + " of " + size + " bytes");
            }
            read += n;
        }
        return buf;
    }

    // ── shell v2 frames ────────────────────────────────────────────

    /**
     * Parses the {@code shell,v2,raw:} stream: frames are
     * [id:u8][length:u32 LE][payload]. Id 1 = stdout, 2 = stderr,
     * 3 = exit (1-byte payload), 4 = close-stdin. WRTE payloads may
     * split frames across messages, so feed bytes incrementally.
     */
    public static final class ShellV2Reader {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final StringBuilder stdout = new StringBuilder();
        private final StringBuilder stderr = new StringBuilder();
        private Integer exitCode;

        /** Feeds one WRTE payload; returns any newly completed frames. */
        public List<String> feed(byte[] data) {
            List<String> events = new ArrayList<>();
            buffer.write(data, 0, data.length);
            byte[] bytes = buffer.toByteArray();
            int pos = 0;
            while (bytes.length - pos >= 5) {
                int id = bytes[pos] & 0xff;
                int len = (bytes[pos + 1] & 0xff)
                        | ((bytes[pos + 2] & 0xff) << 8)
                        | ((bytes[pos + 3] & 0xff) << 16)
                        | ((bytes[pos + 4] & 0xff) << 24);
                if (len < 0 || len > 1024 * 1024 || bytes.length - pos - 5 < len) {
                    break;
                }
                byte[] payload = new byte[len];
                System.arraycopy(bytes, pos + 5, payload, 0, len);
                pos += 5 + len;
                switch (id) {
                    case 1:
                        stdout.append(new String(payload, java.nio.charset.StandardCharsets.UTF_8));
                        events.add("stdout");
                        break;
                    case 2:
                        stderr.append(new String(payload, java.nio.charset.StandardCharsets.UTF_8));
                        events.add("stderr");
                        break;
                    case 3:
                        if (payload.length >= 1) {
                            exitCode = payload[0] & 0xff;
                        }
                        events.add("exit");
                        break;
                    case 4:
                        events.add("close-stdin");
                        break;
                    default:
                        events.add("unknown-frame-" + id);
                        break;
                }
            }
            if (pos > 0) {
                byte[] rest = new byte[bytes.length - pos];
                System.arraycopy(bytes, pos, rest, 0, rest.length);
                buffer.reset();
                buffer.write(rest, 0, rest.length);
            }
            return events;
        }

        public String stdout() {
            return stdout.toString();
        }

        public String stderr() {
            return stderr.toString();
        }

        public Integer exitCode() {
            return exitCode;
        }
    }
}
