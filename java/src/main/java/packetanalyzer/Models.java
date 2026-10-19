package packetanalyzer;

import java.time.Instant;
import java.util.Locale;

public final class Models {
    private Models() {}

    public enum AppType {
        UNKNOWN, HTTP, HTTPS, DNS, TLS, QUIC, GOOGLE, FACEBOOK, YOUTUBE, TWITTER,
        INSTAGRAM, NETFLIX, AMAZON, MICROSOFT, APPLE, WHATSAPP, TELEGRAM, TIKTOK,
        SPOTIFY, ZOOM, DISCORD, GITHUB, CLOUDFLARE
    }

    public enum ConnectionState { NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED }
    public enum PacketAction { FORWARD, DROP, INSPECT, LOG_ONLY }

    public record FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        @Override
        public String toString() {
            return ipToString(srcIp) + ":" + srcPort + " -> " + ipToString(dstIp) + ":"
                    + dstPort + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
        }
    }

    public record PcapGlobalHeader(byte[] raw, int versionMajor, int versionMinor,
                                   int snaplen, long network, boolean littleEndian,
                                   boolean nanosecondTimestamps) {}

    public record PcapPacketHeader(long timestampSeconds, long timestampFraction,
                                   long includedLength, long originalLength) {}

    public record RawPacket(PcapPacketHeader header, byte[] data) {}

    public static final class ParsedPacket {
        public long timestampSeconds;
        public long timestampFraction;
        public String srcMac = "";
        public String destMac = "";
        public int etherType;
        public boolean hasIp;
        public int ipVersion;
        public String srcIp = "";
        public String destIp = "";
        public int protocol;
        public int ttl;
        public boolean hasTcp;
        public boolean hasUdp;
        public int srcPort;
        public int destPort;
        public long seqNumber;
        public long ackNumber;
        public int tcpFlags;
        public int payloadOffset;
        public byte[] payload = new byte[0];
    }

    public static final class Connection {
        public final FiveTuple tuple;
        public ConnectionState state = ConnectionState.NEW;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packetsIn;
        public long packetsOut;
        public long bytesIn;
        public long bytesOut;
        public Instant firstSeen = Instant.now();
        public volatile Instant lastSeen = firstSeen;
        public PacketAction action = PacketAction.FORWARD;
        public boolean synSeen;
        public boolean synAckSeen;
        public boolean finSeen;

        public Connection(FiveTuple tuple) {
            this.tuple = tuple;
        }
    }

    public record PacketJob(int packetId, long timestampSeconds, long timestampFraction,
                            FiveTuple tuple, byte[] data, int tcpFlags,
                            int payloadOffset, int payloadLength) {
        public static PacketJob endOfStream() {
            return new PacketJob(-1, 0, 0, null, new byte[0], 0, 0, 0);
        }

        public boolean isEndOfStream() {
            return packetId < 0;
        }
    }

    public static String ipToString(int ip) {
        return (ip >>> 24 & 0xff) + "." + (ip >>> 16 & 0xff) + "."
                + (ip >>> 8 & 0xff) + "." + (ip & 0xff);
    }

    public static int parseIp(String value) {
        String[] octets = value.trim().split("\\.", -1);
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + value);
        }
        int address = 0;
        for (String octet : octets) {
            int part;
            try {
                part = Integer.parseInt(octet);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value, exception);
            }
            if (part < 0 || part > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            }
            address = (address << 8) | part;
        }
        return address;
    }

    public static String appTypeToString(AppType type) {
        return switch (type) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
        };
    }

    public static AppType sniToAppType(String sni) {
        String domain = sni.toLowerCase(Locale.ROOT);
        if (hasDomainLabel(domain, "youtube", "ytimg", "youtu.be")) return AppType.YOUTUBE;
        if (hasDomainLabel(domain, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")) return AppType.FACEBOOK;
        if (hasDomainLabel(domain, "instagram", "cdninstagram")) return AppType.INSTAGRAM;
        if (hasDomainLabel(domain, "whatsapp", "wa.me")) return AppType.WHATSAPP;
        if (hasDomainLabel(domain, "twitter", "twimg", "x.com", "t.co")) return AppType.TWITTER;
        if (hasDomainLabel(domain, "netflix", "nflxvideo", "nflximg")) return AppType.NETFLIX;
        if (hasDomainLabel(domain, "amazon", "amazonaws", "cloudfront", "aws")) return AppType.AMAZON;
        if (hasDomainLabel(domain, "microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")) return AppType.MICROSOFT;
        if (hasDomainLabel(domain, "apple", "icloud", "mzstatic", "itunes")) return AppType.APPLE;
        if (hasDomainLabel(domain, "telegram", "t.me")) return AppType.TELEGRAM;
        if (hasDomainLabel(domain, "tiktok", "musical.ly", "bytedance")) return AppType.TIKTOK;
        if (hasDomainLabel(domain, "spotify", "scdn.co")) return AppType.SPOTIFY;
        if (hasDomainLabel(domain, "zoom")) return AppType.ZOOM;
        if (hasDomainLabel(domain, "discord", "discordapp")) return AppType.DISCORD;
        if (hasDomainLabel(domain, "github", "githubusercontent")) return AppType.GITHUB;
        if (hasDomainLabel(domain, "cloudflare") || domain.contains("cf-")) return AppType.CLOUDFLARE;
        if (hasDomainLabel(domain, "google", "gstatic", "googleapis", "ggpht", "gvt1")) return AppType.GOOGLE;
        return domain.isEmpty() ? AppType.UNKNOWN : AppType.HTTPS;
    }

    private static boolean hasDomainLabel(String domain, String... patterns) {
        for (String pattern : patterns) {
            if (pattern.indexOf('.') >= 0) {
                if (domain.equals(pattern) || domain.endsWith("." + pattern)) return true;
            } else {
                for (String label : domain.split("\\.")) {
                    if (label.equals(pattern)) return true;
                }
            }
        }
        return false;
    }
}
