package packetanalyzer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static packetanalyzer.Models.*;

public final class RuleManager {
    public enum ReasonType { IP, APP, DOMAIN, PORT }
    public record BlockReason(ReasonType type, String detail) {}
    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<Integer> blockedPorts = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final Set<String> domainPatterns = ConcurrentHashMap.newKeySet();

    public void blockIp(String ip) { blockedIps.add(parseIp(ip)); }
    public void unblockIp(String ip) { blockedIps.remove(parseIp(ip)); }
    public void blockApp(AppType app) { blockedApps.add(app); }
    public void unblockApp(AppType app) { blockedApps.remove(app); }
    public void blockPort(int port) {
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Invalid port: " + port);
        blockedPorts.add(port);
    }
    public void unblockPort(int port) { blockedPorts.remove(port); }

    public void blockDomain(String domain) {
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty()) throw new IllegalArgumentException("Domain rule cannot be empty");
        (normalized.contains("*") ? domainPatterns : blockedDomains).add(normalized);
    }

    public void unblockDomain(String domain) {
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        domainPatterns.remove(normalized);
        blockedDomains.remove(normalized);
    }

    public boolean isDomainBlocked(String domain) {
        String normalized = domain.toLowerCase(Locale.ROOT);
        if (blockedDomains.contains(normalized)) return true;
        for (String pattern : domainPatterns) {
            if (domainMatchesPattern(normalized, pattern)) return true;
        }
        return false;
    }

    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (blockedIps.contains(srcIp)) return new BlockReason(ReasonType.IP, ipToString(srcIp));
        if (blockedPorts.contains(dstPort)) return new BlockReason(ReasonType.PORT, Integer.toString(dstPort));
        if (blockedApps.contains(app)) return new BlockReason(ReasonType.APP, appTypeToString(app));
        if (!domain.isEmpty() && isDomainBlocked(domain)) return new BlockReason(ReasonType.DOMAIN, domain);
        return null;
    }

    public RuleStats getStats() {
        return new RuleStats(blockedIps.size(), blockedApps.size(),
                blockedDomains.size() + domainPatterns.size(), blockedPorts.size());
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedPorts.clear();
        blockedDomains.clear();
        domainPatterns.clear();
    }

    public void loadRules(Path path) throws IOException {
        String section = "";
        for (String rawLine : Files.readAllLines(path)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.toUpperCase(Locale.ROOT);
                continue;
            }
            switch (section) {
                case "[BLOCKED_IPS]" -> blockIp(line);
                case "[BLOCKED_APPS]" -> blockApp(parseAppType(line));
                case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                default -> throw new IOException("Unknown or missing rules section for: " + line);
            }
        }
    }

    public void saveRules(Path path) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add("[BLOCKED_IPS]");
        blockedIps.stream().sorted().map(Models::ipToString).forEach(lines::add);
        lines.add("");
        lines.add("[BLOCKED_APPS]");
        blockedApps.stream().sorted().map(Models::appTypeToString).forEach(lines::add);
        lines.add("");
        lines.add("[BLOCKED_DOMAINS]");
        blockedDomains.stream().sorted().forEach(lines::add);
        domainPatterns.stream().sorted().forEach(lines::add);
        lines.add("");
        lines.add("[BLOCKED_PORTS]");
        blockedPorts.stream().sorted().map(String::valueOf).forEach(lines::add);
        Files.write(path, lines);
    }

    public static AppType parseAppType(String name) throws IOException {
        for (AppType type : AppType.values()) {
            if (appTypeToString(type).equalsIgnoreCase(name.trim())
                    || type.name().equalsIgnoreCase(name.trim())) return type;
        }
        throw new IOException("Unknown application type: " + name);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            return domain.endsWith(suffix) || domain.equals(pattern.substring(2));
        }
        if (pattern.startsWith("*")) return domain.endsWith(pattern.substring(1));
        return domain.equals(pattern);
    }
}
