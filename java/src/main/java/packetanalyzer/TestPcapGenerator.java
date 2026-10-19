package packetanalyzer;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;

import static packetanalyzer.Models.parseIp;

public final class TestPcapGenerator {
    private static final Random RANDOM = new Random();
    private static final String USER_MAC = "00:11:22:33:44:55";
    private static final String GATEWAY_MAC = "aa:bb:cc:dd:ee:ff";
    private static final String USER_IP = "192.168.1.100";
    private static long timestamp = 1_700_000_000L;

    private TestPcapGenerator() {}

    public static void main(String[] args) throws IOException {
        Path output = Path.of(args.length == 0 ? "test_dpi.pcap" : args[0]);
        List<String[]> tlsConnections = List.of(
                new String[]{"142.250.185.206", "www.google.com"},
                new String[]{"142.250.185.110", "www.youtube.com"},
                new String[]{"157.240.1.35", "www.facebook.com"},
                new String[]{"157.240.1.174", "www.instagram.com"},
                new String[]{"104.244.42.65", "twitter.com"},
                new String[]{"52.94.236.248", "www.amazon.com"},
                new String[]{"23.52.167.61", "www.netflix.com"},
                new String[]{"140.82.114.4", "github.com"},
                new String[]{"104.16.85.20", "discord.com"},
                new String[]{"35.186.224.25", "zoom.us"},
                new String[]{"35.186.227.140", "web.telegram.org"},
                new String[]{"99.86.0.100", "www.tiktok.com"},
                new String[]{"35.186.224.47", "open.spotify.com"},
                new String[]{"192.0.78.24", "www.cloudflare.com"},
                new String[]{"13.107.42.14", "www.microsoft.com"},
                new String[]{"17.253.144.10", "www.apple.com"});
        List<String[]> httpConnections = List.of(
                new String[]{"93.184.216.34", "example.com"},
                new String[]{"185.199.108.153", "httpbin.org"});
        List<String> dnsQueries = List.of(
                "www.google.com", "www.youtube.com", "www.facebook.com", "api.twitter.com");
        int sequence = 1000;

        try (DataOutputStream file = new DataOutputStream(Files.newOutputStream(output))) {
            file.write(littleEndian(0xa1b2c3d4, 4));
            file.write(littleEndian(2, 2));
            file.write(littleEndian(4, 2));
            file.write(littleEndian(0, 4));
            file.write(littleEndian(0, 4));
            file.write(littleEndian(65535, 4));
            file.write(littleEndian(1, 4));

            for (String[] target : tlsConnections) {
                int sourcePort = randomSourcePort();
                byte[] ethernet = ethernetHeader(USER_MAC, GATEWAY_MAC);
                byte[] tcp = tcpHeader(sourcePort, 443, sequence, 0, 0x02);
                writePacket(file, combine(ethernet, ipv4Header(USER_IP, target[0], 6, tcp.length), tcp));

                tcp = tcpHeader(443, sourcePort, sequence + 1000, sequence + 1, 0x12);
                writePacket(file, combine(ethernetHeader(GATEWAY_MAC, USER_MAC),
                        ipv4Header(target[0], USER_IP, 6, tcp.length), tcp));

                tcp = tcpHeader(sourcePort, 443, sequence + 1, sequence + 1001, 0x10);
                writePacket(file, combine(ethernet, ipv4Header(USER_IP, target[0], 6, tcp.length), tcp));

                byte[] tls = tlsClientHello(target[1]);
                tcp = tcpHeader(sourcePort, 443, sequence + 1, sequence + 1001, 0x18);
                writePacket(file, combine(ethernet, ipv4Header(USER_IP, target[0], 6, tcp.length + tls.length),
                        tcp, tls));
                sequence += 10_000;
            }

            for (String[] target : httpConnections) {
                int sourcePort = randomSourcePort();
                byte[] ethernet = ethernetHeader(USER_MAC, GATEWAY_MAC);
                byte[] tcp = tcpHeader(sourcePort, 80, sequence, 0, 0x02);
                writePacket(file, combine(ethernet, ipv4Header(USER_IP, target[0], 6, tcp.length), tcp));
                byte[] request = ("GET / HTTP/1.1\r\nHost: " + target[1]
                        + "\r\nUser-Agent: DPI-Test/1.0\r\nAccept: */*\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII);
                tcp = tcpHeader(sourcePort, 80, sequence + 1, 1, 0x18);
                writePacket(file, combine(ethernet, ipv4Header(USER_IP, target[0], 6,
                        tcp.length + request.length), tcp, request));
                sequence += 10_000;
            }

            for (String domain : dnsQueries) {
                int sourcePort = randomSourcePort();
                byte[] dns = dnsQuery(domain);
                byte[] udp = udpHeader(sourcePort, 53, dns.length);
                writePacket(file, combine(ethernetHeader(USER_MAC, GATEWAY_MAC),
                        ipv4Header(USER_IP, "8.8.8.8", 17, udp.length + dns.length), udp, dns));
            }

            String blockedSourceIp = "192.168.1.50";
            for (int i = 0; i < 5; i++) {
                int sourcePort = randomSourcePort();
                byte[] tcp = tcpHeader(sourcePort, 443, sequence, 0, 0x02);
                writePacket(file, combine(ethernetHeader("00:11:22:33:44:56", GATEWAY_MAC),
                        ipv4Header(blockedSourceIp, "172.217.0.100", 6, tcp.length), tcp));
                sequence += 1000;
            }
        }
        System.out.printf("Created %s with test traffic%n", output);
        System.out.printf("  - %d TLS connections with SNI%n", tlsConnections.size());
        System.out.printf("  - %d HTTP connections%n", httpConnections.size());
        System.out.printf("  - %d DNS queries%n", dnsQueries.size());
        System.out.println("  - 5 packets from blocked IP 192.168.1.50");
    }

    private static void writePacket(DataOutputStream file, byte[] data) throws IOException {
        file.write(littleEndian(timestamp++, 4));
        file.write(littleEndian(RANDOM.nextInt(1_000_000), 4));
        file.write(littleEndian(data.length, 4));
        file.write(littleEndian(data.length, 4));
        file.write(data);
    }

    private static byte[] ethernetHeader(String sourceMac, String destinationMac) {
        byte[] header = new byte[14];
        copyMac(destinationMac, header, 0);
        copyMac(sourceMac, header, 6);
        putU16(header, 12, 0x0800);
        return header;
    }

    private static byte[] ipv4Header(String sourceIp, String destinationIp, int protocol, int payloadLength) {
        byte[] header = new byte[20];
        header[0] = 0x45;
        putU16(header, 2, 20 + payloadLength);
        putU16(header, 4, RANDOM.nextInt(1, 65_536));
        putU16(header, 6, 0x4000);
        header[8] = 64;
        header[9] = (byte) protocol;
        putIp(header, 12, sourceIp);
        putIp(header, 16, destinationIp);
        return header;
    }

    private static byte[] tcpHeader(int sourcePort, int destinationPort, long sequence,
                                    long acknowledgment, int flags) {
        byte[] header = new byte[20];
        putU16(header, 0, sourcePort);
        putU16(header, 2, destinationPort);
        putU32(header, 4, sequence);
        putU32(header, 8, acknowledgment);
        header[12] = 0x50;
        header[13] = (byte) flags;
        putU16(header, 14, 65_535);
        return header;
    }

    private static byte[] udpHeader(int sourcePort, int destinationPort, int payloadLength) {
        byte[] header = new byte[8];
        putU16(header, 0, sourcePort);
        putU16(header, 2, destinationPort);
        putU16(header, 4, 8 + payloadLength);
        return header;
    }

    private static byte[] tlsClientHello(String serverName) {
        byte[] name = serverName.getBytes(StandardCharsets.US_ASCII);
        byte[] nameEntry = combine(new byte[]{0}, bigEndian(name.length, 2), name);
        byte[] serverNameList = combine(bigEndian(nameEntry.length, 2), nameEntry);
        byte[] sniExtension = combine(bigEndian(0, 2), bigEndian(serverNameList.length, 2), serverNameList);
        byte[] versionsExtension = combine(bigEndian(0x002b, 2), bigEndian(3, 2),
                new byte[]{2}, bigEndian(0x0304, 2));
        byte[] extensions = combine(sniExtension, versionsExtension);
        byte[] body = combine(bigEndian(0x0303, 2), randomBytes(32),
                new byte[]{0}, bigEndian(4, 2), bigEndian(0x1301, 2), bigEndian(0x1302, 2),
                new byte[]{1, 0}, bigEndian(extensions.length, 2), extensions);
        byte[] handshake = combine(new byte[]{1}, bigEndian(body.length, 3), body);
        return combine(new byte[]{0x16}, bigEndian(0x0301, 2), bigEndian(handshake.length, 2), handshake);
    }

    private static byte[] dnsQuery(String domain) {
        byte[] questionName = new byte[]{0};
        for (String label : domain.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length == 0 || bytes.length > 63) throw new IllegalArgumentException("Invalid DNS label");
            questionName = combine(questionName.length == 1 && questionName[0] == 0
                    ? new byte[0] : questionName, new byte[]{(byte) bytes.length}, bytes);
        }
        questionName = combine(questionName, new byte[]{0}, bigEndian(1, 2), bigEndian(1, 2));
        byte[] header = combine(bigEndian(RANDOM.nextInt(1, 65_536), 2), bigEndian(0x0100, 2),
                bigEndian(1, 2), bigEndian(0, 2), bigEndian(0, 2), bigEndian(0, 2));
        return combine(header, questionName);
    }

    private static int randomSourcePort() { return RANDOM.nextInt(49_152, 65_536); }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static void copyMac(String address, byte[] target, int offset) {
        String[] bytes = address.split(":");
        for (int i = 0; i < 6; i++) target[offset + i] = (byte) Integer.parseInt(bytes[i], 16);
    }

    private static void putIp(byte[] target, int offset, String address) {
        int ip = parseIp(address);
        target[offset] = (byte) (ip >>> 24);
        target[offset + 1] = (byte) (ip >>> 16);
        target[offset + 2] = (byte) (ip >>> 8);
        target[offset + 3] = (byte) ip;
    }

    private static byte[] combine(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length = Math.addExact(length, part.length);
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    private static void putU16(byte[] target, int offset, int value) {
        target[offset] = (byte) (value >>> 8);
        target[offset + 1] = (byte) value;
    }

    private static void putU32(byte[] target, int offset, long value) {
        target[offset] = (byte) (value >>> 24);
        target[offset + 1] = (byte) (value >>> 16);
        target[offset + 2] = (byte) (value >>> 8);
        target[offset + 3] = (byte) value;
    }

    private static byte[] bigEndian(long value, int bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(bytes).order(ByteOrder.BIG_ENDIAN);
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) buffer.put((byte) (value >>> shift));
        return buffer.array();
    }

    private static byte[] littleEndian(long value, int bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(bytes).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < bytes; i++) buffer.put((byte) (value >>> (i * 8)));
        return buffer.array();
    }
}
