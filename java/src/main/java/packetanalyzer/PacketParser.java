package packetanalyzer;

import java.util.Arrays;
import static packetanalyzer.Models.*;

public final class PacketParser {
    public static final int ETHERNET_IPV4 = 0x0800;
    public static final int ETHERNET_IPV6 = 0x86dd;
    public static final int ETHERNET_ARP = 0x0806;
    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    private PacketParser() {}

    public static ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data();
        if (data.length < 14) return null;
        ParsedPacket parsed = new ParsedPacket();
        parsed.timestampSeconds = raw.header().timestampSeconds();
        parsed.timestampFraction = raw.header().timestampFraction();
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = unsignedShort(data, 12);
        int offset = 14;

        if (parsed.etherType == ETHERNET_IPV4) {
            if (data.length < offset + 20) return null;
            int versionAndLength = data[offset] & 0xff;
            parsed.ipVersion = versionAndLength >>> 4;
            int ipHeaderLength = (versionAndLength & 0x0f) * 4;
            if (parsed.ipVersion != 4 || ipHeaderLength < 20 || data.length < offset + ipHeaderLength) return null;
            parsed.ttl = data[offset + 8] & 0xff;
            parsed.protocol = data[offset + 9] & 0xff;
            parsed.srcIp = ipToString(intAt(data, offset + 12));
            parsed.destIp = ipToString(intAt(data, offset + 16));
            parsed.hasIp = true;
            offset += ipHeaderLength;
            if (parsed.protocol == PROTOCOL_TCP) {
                if (data.length < offset + 20) return null;
                parsed.srcPort = unsignedShort(data, offset);
                parsed.destPort = unsignedShort(data, offset + 2);
                parsed.seqNumber = Integer.toUnsignedLong(intAt(data, offset + 4));
                parsed.ackNumber = Integer.toUnsignedLong(intAt(data, offset + 8));
                int tcpHeaderLength = ((data[offset + 12] & 0xff) >>> 4) * 4;
                parsed.tcpFlags = data[offset + 13] & 0xff;
                if (tcpHeaderLength < 20 || data.length < offset + tcpHeaderLength) return null;
                parsed.hasTcp = true;
                offset += tcpHeaderLength;
            } else if (parsed.protocol == PROTOCOL_UDP) {
                if (data.length < offset + 8) return null;
                parsed.srcPort = unsignedShort(data, offset);
                parsed.destPort = unsignedShort(data, offset + 2);
                parsed.hasUdp = true;
                offset += 8;
            }
        }
        parsed.payloadOffset = offset;
        parsed.payload = Arrays.copyOfRange(data, offset, data.length);
        return parsed;
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case PROTOCOL_ICMP -> "ICMP";
            case PROTOCOL_TCP -> "TCP";
            case PROTOCOL_UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        appendFlag(result, flags, 0x02, "SYN");
        appendFlag(result, flags, 0x10, "ACK");
        appendFlag(result, flags, 0x01, "FIN");
        appendFlag(result, flags, 0x04, "RST");
        appendFlag(result, flags, 0x08, "PSH");
        appendFlag(result, flags, 0x20, "URG");
        return result.isEmpty() ? "none" : result.toString();
    }

    private static void appendFlag(StringBuilder target, int flags, int mask, String name) {
        if ((flags & mask) != 0) {
            if (!target.isEmpty()) target.append(' ');
            target.append(name);
        }
    }

    private static String macToString(byte[] bytes, int offset) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i != 0) result.append(':');
            result.append(String.format("%02x", bytes[offset + i] & 0xff));
        }
        return result.toString();
    }

    private static int unsignedShort(byte[] data, int offset) {
        return (data[offset] & 0xff) << 8 | data[offset + 1] & 0xff;
    }

    private static int intAt(byte[] data, int offset) {
        return (data[offset] & 0xff) << 24 | (data[offset + 1] & 0xff) << 16
                | (data[offset + 2] & 0xff) << 8 | data[offset + 3] & 0xff;
    }
}
