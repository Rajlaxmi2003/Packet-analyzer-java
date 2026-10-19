package packetanalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import static packetanalyzer.Models.*;

public final class PacketAnalyzerMain {
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ROOT).withZone(ZoneId.systemDefault());

    private PacketAnalyzerMain() {}

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException | IOException exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printUsage();
            return;
        }
        int maxPackets = -1;
        if (args.length > 1) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("max_packets must be an integer", exception);
            }
            if (maxPackets == 0 || maxPackets < -1) {
                throw new IllegalArgumentException("max_packets must be positive, or -1 for unlimited");
            }
        }

        int packetCount = 0;
        int parseErrors = 0;
        try (PcapReader reader = new PcapReader()) {
            PcapGlobalHeader header = reader.open(Path.of(args[0]));
            if (header.network() != 1) {
                throw new IOException("Unsupported PCAP link type " + header.network() + "; Ethernet is required");
            }
            System.out.printf("Opened PCAP file: %s%n  Version: %d.%d%n  Snaplen: %d bytes%n  Link type: %d%s%n",
                    args[0], header.versionMajor(), header.versionMinor(), header.snaplen(),
                    header.network(), header.network() == 1 ? " (Ethernet)" : "");
            System.out.println("\n--- Reading packets ---");
            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                packetCount++;
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null) {
                    System.err.printf("Warning: Failed to parse packet #%d%n", packetCount);
                    parseErrors++;
                } else {
                    printPacketSummary(parsed, packetCount);
                }
                if (maxPackets > 0 && packetCount >= maxPackets) {
                    System.out.printf("%n(Stopped after %d packets)%n", maxPackets);
                    break;
                }
            }
        }
        System.out.println("\n====================================");
        System.out.println("Summary:");
        System.out.printf("  Total packets read:  %d%n  Parse errors:        %d%n", packetCount, parseErrors);
        System.out.println("====================================");
    }

    private static void printPacketSummary(ParsedPacket packet, int packetNumber) {
        Instant timestamp = Instant.ofEpochSecond(packet.timestampSeconds);
        System.out.printf("%n========== Packet #%d ==========%n", packetNumber);
        System.out.printf("Time: %s.%06d%n", TIME_FORMAT.format(timestamp), packet.timestampFraction);
        System.out.println("\n[Ethernet]");
        System.out.printf("  Source MAC:      %s%n  Destination MAC: %s%n  EtherType:       0x%04x",
                packet.srcMac, packet.destMac, packet.etherType);
        if (packet.etherType == PacketParser.ETHERNET_IPV4) System.out.print(" (IPv4)");
        else if (packet.etherType == PacketParser.ETHERNET_IPV6) System.out.print(" (IPv6)");
        else if (packet.etherType == PacketParser.ETHERNET_ARP) System.out.print(" (ARP)");
        System.out.println();
        if (packet.hasIp) {
            System.out.printf("%n[IPv%d]%n  Source IP:      %s%n  Destination IP: %s%n  Protocol:       %s%n  TTL:            %d%n",
                    packet.ipVersion, packet.srcIp, packet.destIp,
                    PacketParser.protocolToString(packet.protocol), packet.ttl);
        }
        if (packet.hasTcp) {
            System.out.printf("%n[TCP]%n  Source Port:      %d%n  Destination Port: %d%n  Sequence Number:  %d%n  Ack Number:       %d%n  Flags:            %s%n",
                    packet.srcPort, packet.destPort, packet.seqNumber,
                    packet.ackNumber, PacketParser.tcpFlagsToString(packet.tcpFlags));
        }
        if (packet.hasUdp) {
            System.out.printf("%n[UDP]%n  Source Port:      %d%n  Destination Port: %d%n",
                    packet.srcPort, packet.destPort);
        }
        if (packet.payload.length > 0) {
            System.out.printf("%n[Payload]%n  Length: %d bytes%n  Preview: ", packet.payload.length);
            for (int i = 0; i < Math.min(packet.payload.length, 32); i++) {
                System.out.printf("%02x ", packet.payload[i] & 0xff);
            }
            if (packet.payload.length > 32) System.out.print("...");
            System.out.println();
        }
    }

    private static void printUsage() {
        System.out.println("""
                Packet Analyzer - Java PCAP reader

                Usage: java -cp build/classes packetanalyzer.PacketAnalyzerMain <pcap_file> [max_packets]

                Arguments:
                  pcap_file   Path to a classic .pcap file
                  max_packets Optional positive limit; omit for all packets
                """);
    }
}
