package packetanalyzer;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

import static packetanalyzer.Models.*;

public final class PcapReader implements Closeable {
    private InputStream input;
    private PcapGlobalHeader globalHeader;

    public PcapGlobalHeader open(Path path) throws IOException {
        close();
        input = Files.newInputStream(path);
        byte[] raw = readExactly(input, 24, false);
        int magic = ByteBuffer.wrap(raw, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        boolean littleEndian;
        boolean nanos;
        switch (magic) {
            case 0xa1b2c3d4 -> { littleEndian = false; nanos = false; }
            case 0xd4c3b2a1 -> { littleEndian = true; nanos = false; }
            case 0xa1b23c4d -> { littleEndian = false; nanos = true; }
            case 0x4d3cb2a1 -> { littleEndian = true; nanos = true; }
            default -> {
                close();
                throw new IOException(String.format("Invalid PCAP magic number: 0x%08x", magic));
            }
        }
        ByteBuffer header = ByteBuffer.wrap(raw).order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        header.position(4);
        int major = Short.toUnsignedInt(header.getShort());
        int minor = Short.toUnsignedInt(header.getShort());
        header.getInt();
        header.getInt();
        long snaplen = Integer.toUnsignedLong(header.getInt());
        long network = Integer.toUnsignedLong(header.getInt());
        if (snaplen == 0 || snaplen > 16 * 1024 * 1024) {
            close();
            throw new IOException("Invalid PCAP snapshot length: " + snaplen);
        }
        globalHeader = new PcapGlobalHeader(raw, major, minor, (int) snaplen, network, littleEndian, nanos);
        return globalHeader;
    }

    public PcapGlobalHeader getGlobalHeader() {
        if (globalHeader == null) throw new IllegalStateException("PCAP file has not been opened");
        return globalHeader;
    }

    public RawPacket readNextPacket() throws IOException {
        if (input == null || globalHeader == null) throw new IllegalStateException("PCAP file has not been opened");
        byte[] rawHeader = readExactly(input, 16, true);
        if (rawHeader == null) return null;
        ByteBuffer header = ByteBuffer.wrap(rawHeader).order(globalHeader.littleEndian()
                ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        long seconds = Integer.toUnsignedLong(header.getInt());
        long fraction = Integer.toUnsignedLong(header.getInt());
        long included = Integer.toUnsignedLong(header.getInt());
        long original = Integer.toUnsignedLong(header.getInt());
        if (included > globalHeader.snaplen() || included > 16 * 1024 * 1024) {
            throw new IOException("Invalid packet length: " + included);
        }
        byte[] data = readExactly(input, (int) included, false);
        if (data == null) throw new EOFException("Truncated packet data in PCAP file");
        return new RawPacket(new PcapPacketHeader(seconds, fraction, included, original), data);
    }

    @Override
    public void close() throws IOException {
        if (input != null) {
            input.close();
            input = null;
        }
        globalHeader = null;
    }

    private static byte[] readExactly(InputStream input, int length, boolean allowCleanEof) throws IOException {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(bytes, offset, length - offset);
            if (count < 0) {
                if (allowCleanEof && offset == 0) return null;
                throw new EOFException(offset == 0 ? "Unexpected end of PCAP file" : "Truncated PCAP record");
            }
            offset += count;
        }
        return bytes;
    }
}
