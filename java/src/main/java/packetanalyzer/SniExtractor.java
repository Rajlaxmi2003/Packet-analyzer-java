package packetanalyzer;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public final class SniExtractor {
    private SniExtractor() {}

    public static Optional<String> extractTlsServerName(byte[] payload) {
        if (payload.length < 9 || (payload[0] & 0xff) != 0x16) return Optional.empty();
        int version = readU16(payload, 1);
        int recordLength = readU16(payload, 3);
        if (version < 0x0300 || version > 0x0304 || recordLength > payload.length - 5
                || (payload[5] & 0xff) != 1) return Optional.empty();

        int offset = 9;
        if (offset + 34 > payload.length) return Optional.empty();
        offset += 34;
        if (offset >= payload.length) return Optional.empty();
        int sessionLength = payload[offset++] & 0xff;
        offset += sessionLength;
        if (offset + 2 > payload.length) return Optional.empty();
        int cipherLength = readU16(payload, offset);
        offset += 2 + cipherLength;
        if (offset >= payload.length) return Optional.empty();
        int compressionLength = payload[offset++] & 0xff;
        offset += compressionLength;
        if (offset + 2 > payload.length) return Optional.empty();
        int extensionsLength = readU16(payload, offset);
        offset += 2;
        int end = Math.min(payload.length, offset + extensionsLength);

        while (offset + 4 <= end) {
            int type = readU16(payload, offset);
            int length = readU16(payload, offset + 2);
            offset += 4;
            if (offset + length > end) return Optional.empty();
            if (type == 0 && length >= 5) {
                int listLength = readU16(payload, offset);
                int nameType = payload[offset + 2] & 0xff;
                int nameLength = readU16(payload, offset + 3);
                if (listLength >= 3 && nameType == 0 && nameLength <= length - 5) {
                    String name = new String(payload, offset + 5, nameLength, StandardCharsets.US_ASCII);
                    return name.isBlank() ? Optional.empty() : Optional.of(name);
                }
            }
            offset += length;
        }
        return Optional.empty();
    }

    public static Optional<String> extractHttpHost(byte[] payload) {
        if (payload.length < 4) return Optional.empty();
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        int lineEnd = text.indexOf("\r\n");
        if (lineEnd < 0) return Optional.empty();
        String requestLine = text.substring(0, lineEnd);
        if (!requestLine.matches("(?i)^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|CONNECT|TRACE)\\s+.*")) {
            return Optional.empty();
        }
        for (String line : text.substring(lineEnd + 2).split("\\r?\\n")) {
            if (line.isEmpty()) break;
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Host")) {
                String host = line.substring(colon + 1).trim();
                int port = host.lastIndexOf(':');
                if (port > 0 && host.indexOf(':') == port) host = host.substring(0, port);
                return host.isEmpty() ? Optional.empty() : Optional.of(host);
            }
        }
        return Optional.empty();
    }

    public static Optional<String> extractDnsQuery(byte[] payload) {
        if (payload.length < 17 || (payload[2] & 0x80) != 0 || readU16(payload, 4) == 0) {
            return Optional.empty();
        }
        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < payload.length) {
            int labelLength = payload[offset++] & 0xff;
            if (labelLength == 0) break;
            if (labelLength > 63 || offset + labelLength > payload.length) return Optional.empty();
            if (!domain.isEmpty()) domain.append('.');
            domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
            offset += labelLength;
        }
        return domain.isEmpty() ? Optional.empty() : Optional.of(domain.toString());
    }

    public static boolean isQuicInitial(byte[] payload) {
        if (payload.length < 5 || (payload[0] & 0xc0) != 0xc0) return false;
        int packetType = (payload[0] >>> 4) & 0x03;
        return packetType == 0;
    }

    private static int readU16(byte[] data, int offset) {
        return (data[offset] & 0xff) << 8 | data[offset + 1] & 0xff;
    }
}
