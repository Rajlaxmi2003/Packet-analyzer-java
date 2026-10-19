package packetanalyzer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Consumer;

import static packetanalyzer.Models.*;

public final class ConnectionTracker {
    public record TrackerStats(int activeConnections, long totalConnectionsSeen,
                               long classifiedConnections, long blockedConnections) {}

    private final int fpId;
    private final int maxConnections;
    private final ConcurrentHashMap<FiveTuple, Connection> connections = new ConcurrentHashMap<>();
    private final LongAdder totalSeen = new LongAdder();
    private final LongAdder classifiedCount = new LongAdder();
    private final LongAdder blockedCount = new LongAdder();

    public ConnectionTracker(int fpId, int maxConnections) {
        if (maxConnections < 1) throw new IllegalArgumentException("maxConnections must be positive");
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public int getFpId() { return fpId; }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = connections.get(tuple);
        if (existing != null) return existing;
        synchronized (connections) {
            existing = connections.get(tuple);
            if (existing != null) return existing;
            if (connections.size() >= maxConnections) evictOldest();
            Connection created = new Connection(tuple);
            connections.put(tuple, created);
            totalSeen.increment();
            return created;
        }
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection found = connections.get(tuple);
        return found != null ? found : connections.get(tuple.reverse());
    }

    public void updateConnection(Connection connection, int packetSize, boolean outbound) {
        if (connection == null) return;
        synchronized (connection) {
            connection.lastSeen = Instant.now();
            if (outbound) {
                connection.packetsOut++;
                connection.bytesOut += packetSize;
            } else {
                connection.packetsIn++;
                connection.bytesIn += packetSize;
            }
        }
    }

    public void classifyConnection(Connection connection, AppType app, String sni) {
        if (connection == null) return;
        synchronized (connection) {
            if (connection.state != ConnectionState.CLASSIFIED) {
                connection.appType = app;
                connection.sni = sni;
                connection.state = ConnectionState.CLASSIFIED;
                classifiedCount.increment();
            }
        }
    }

    public void blockConnection(Connection connection) {
        if (connection == null) return;
        synchronized (connection) {
            if (connection.state != ConnectionState.BLOCKED) blockedCount.increment();
            connection.state = ConnectionState.BLOCKED;
            connection.action = PacketAction.DROP;
        }
    }

    public void closeConnection(FiveTuple tuple) {
        Connection connection = connections.get(tuple);
        if (connection != null) {
            synchronized (connection) { connection.state = ConnectionState.CLOSED; }
        }
    }

    public int cleanupStale(Duration timeout) {
        Instant threshold = Instant.now().minus(timeout);
        int removed = 0;
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            Connection connection = entry.getValue();
            synchronized (connection) {
                if (connection.lastSeen.isBefore(threshold) || connection.state == ConnectionState.CLOSED) {
                    if (connections.remove(entry.getKey(), connection)) removed++;
                }
            }
        }
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() { return connections.size(); }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen.sum(), classifiedCount.sum(), blockedCount.sum());
    }

    public void clear() { connections.clear(); }

    public void forEach(Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    private void evictOldest() {
        Map.Entry<FiveTuple, Connection> oldest = connections.entrySet().stream()
                .min(Comparator.comparing(entry -> entry.getValue().lastSeen))
                .orElse(null);
        if (oldest != null) connections.remove(oldest.getKey(), oldest.getValue());
    }

    public static final class GlobalConnectionTable {
        public record GlobalStats(int totalActiveConnections, long totalConnectionsSeen,
                                  Map<AppType, Integer> appDistribution,
                                  List<Map.Entry<String, Integer>> topDomains) {}

        private final List<ConnectionTracker> trackers;

        public GlobalConnectionTable(int numberOfTrackers) {
            if (numberOfTrackers < 0) throw new IllegalArgumentException("numberOfTrackers cannot be negative");
            trackers = new ArrayList<>(java.util.Collections.nCopies(numberOfTrackers, null));
        }

        public synchronized void registerTracker(int fpId, ConnectionTracker tracker) {
            if (fpId < 0 || fpId >= trackers.size()) throw new IndexOutOfBoundsException("Invalid tracker id: " + fpId);
            trackers.set(fpId, tracker);
        }

        public synchronized GlobalStats getGlobalStats() {
            int active = 0;
            long seen = 0;
            Map<AppType, Integer> apps = new EnumMap<>(AppType.class);
            Map<String, Integer> domains = new HashMap<>();
            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;
                TrackerStats trackerStats = tracker.getStats();
                active += trackerStats.activeConnections();
                seen += trackerStats.totalConnectionsSeen();
                tracker.forEach(connection -> {
                    synchronized (connection) {
                        apps.merge(connection.appType, 1, Integer::sum);
                        if (!connection.sni.isEmpty()) domains.merge(connection.sni, 1, Integer::sum);
                    }
                });
            }
            List<Map.Entry<String, Integer>> topDomains = domains.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .limit(20).toList();
            return new GlobalStats(active, seen, Map.copyOf(apps), topDomains);
        }

        public String generateReport() {
            GlobalStats stats = getGlobalStats();
            StringBuilder report = new StringBuilder("\nCONNECTION STATISTICS REPORT\n");
            report.append("Active Connections: ").append(stats.totalActiveConnections()).append('\n')
                    .append("Total Connections Seen: ").append(stats.totalConnectionsSeen()).append('\n')
                    .append("APPLICATION BREAKDOWN\n");
            stats.appDistribution().entrySet().stream()
                    .sorted(Map.Entry.<AppType, Integer>comparingByValue().reversed())
                    .forEach(entry -> report.append(String.format("%-20s %8d%n",
                            appTypeToString(entry.getKey()), entry.getValue())));
            if (!stats.topDomains().isEmpty()) report.append("TOP DOMAINS\n");
            stats.topDomains().forEach(entry -> report.append(String.format("%-40s %8d%n",
                    entry.getKey(), entry.getValue())));
            return report.toString();
        }
    }
}
