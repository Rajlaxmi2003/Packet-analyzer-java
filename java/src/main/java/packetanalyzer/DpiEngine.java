package packetanalyzer;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

import static packetanalyzer.Models.*;

public final class DpiEngine {
    public record PacketView(int packetNumber, String sourceIp, String destinationIp,
                             int sourcePort, int destinationPort, String protocol,
                             String application, String domain, String verdict, int bytes) {}

    public record ProcessingReport(long totalPackets, long totalBytes, long tcpPackets,
                                   long udpPackets, long forwardedPackets, long droppedPackets,
                                   int activeConnections, long totalConnectionsSeen,
                                   Map<String, Long> applicationDistribution,
                                   List<PacketView> packets) {}

    public record Config(int numLoadBalancers, int fastPathsPerLoadBalancer,
                         int queueSize, boolean verbose) {
        public Config {
            if (numLoadBalancers < 1 || fastPathsPerLoadBalancer < 1 || queueSize < 1) {
                throw new IllegalArgumentException("Load balancers, fast paths, and queue size must be positive");
            }
            if ((long) numLoadBalancers * fastPathsPerLoadBalancer > 256) {
                throw new IllegalArgumentException("The total number of fast-path workers cannot exceed 256");
            }
        }

        public static Config defaults() {
            return new Config(2, 2, 10_000, false);
        }
    }

    private final Config config;
    private final RuleManager ruleManager = new RuleManager();
    private final LongAdder totalPackets = new LongAdder();
    private final LongAdder totalBytes = new LongAdder();
    private final LongAdder tcpPackets = new LongAdder();
    private final LongAdder udpPackets = new LongAdder();
    private final LongAdder forwardedPackets = new LongAdder();
    private final LongAdder droppedPackets = new LongAdder();
    private final ConcurrentHashMap<AppType, LongAdder> appCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AppType> detectedDomains = new ConcurrentHashMap<>();
    private final List<ConnectionTracker> trackers = new ArrayList<>();
    private final List<LongAdder> workerCounts = new ArrayList<>();
    private final List<LongAdder> loadBalancerCounts = new ArrayList<>();
    private final ConcurrentHashMap<Integer, PacketView> packetViews = new ConcurrentHashMap<>();
    private final ConnectionTracker.GlobalConnectionTable globalConnectionTable;

    public DpiEngine(Config config) {
        this.config = config;
        int workerCount = config.numLoadBalancers() * config.fastPathsPerLoadBalancer();
        for (int i = 0; i < workerCount; i++) {
            ConnectionTracker tracker = new ConnectionTracker(i);
            trackers.add(tracker);
            workerCounts.add(new LongAdder());
        }
        for (int i = 0; i < config.numLoadBalancers(); i++) loadBalancerCounts.add(new LongAdder());
        globalConnectionTable = new ConnectionTracker.GlobalConnectionTable(workerCount);
        for (int i = 0; i < workerCount; i++) globalConnectionTable.registerTracker(i, trackers.get(i));
    }

    public RuleManager getRuleManager() { return ruleManager; }

    public void blockIp(String ip) { ruleManager.blockIp(ip); }
    public void blockApp(String app) throws IOException { ruleManager.blockApp(RuleManager.parseAppType(app)); }
    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }

    public void loadRules(Path path) throws IOException { ruleManager.loadRules(path); }

    public ProcessingReport processFile(Path inputPath, Path outputPath) throws IOException, InterruptedException {
        if (inputPath.toAbsolutePath().normalize().equals(outputPath.toAbsolutePath().normalize())) {
            throw new IOException("Input and output PCAP paths must be different");
        }
        System.out.println("[DPI] Processing: " + inputPath);
        System.out.println("[DPI] Output to:  " + outputPath);
        try (PcapReader reader = new PcapReader()) {
            PcapGlobalHeader header = reader.open(inputPath);
            if (header.network() != 1) {
                throw new IOException("Unsupported PCAP link type " + header.network() + "; Ethernet is required");
            }
            Path parent = outputPath.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(outputPath))) {
                output.write(header.raw());
                processPackets(reader, header, output);
            }
        }
        ProcessingReport report = getProcessingReport();
        printReport(report);
        return report;
    }

    private void processPackets(PcapReader reader, PcapGlobalHeader header,
                                DataOutputStream output) throws IOException, InterruptedException {
        int workerCount = trackers.size();
        List<BlockingQueue<PacketJob>> workerQueues = new ArrayList<>(workerCount);
        List<BlockingQueue<PacketJob>> loadBalancerQueues = new ArrayList<>(config.numLoadBalancers());
        BlockingQueue<PacketJob> outputQueue = new ArrayBlockingQueue<>(config.queueSize());
        AtomicReference<IOException> outputFailure = new AtomicReference<>();
        AtomicReference<IOException> workerFailure = new AtomicReference<>();
        for (int i = 0; i < workerCount; i++) {
            workerQueues.add(new ArrayBlockingQueue<>(config.queueSize()));
        }
        for (int i = 0; i < config.numLoadBalancers(); i++) {
            loadBalancerQueues.add(new ArrayBlockingQueue<>(config.queueSize()));
        }

        Thread outputThread = new Thread(() -> writeOutput(outputQueue, output, header, outputFailure),
                "pcap-output-writer");
        List<Thread> workers = new ArrayList<>(workerCount);
        List<Thread> loadBalancers = new ArrayList<>(config.numLoadBalancers());
        for (int i = 0; i < workerCount; i++) {
            int workerId = i;
            Thread worker = new Thread(() -> runWorker(workerId, workerQueues.get(workerId),
                    outputQueue, workerFailure),
                    "dpi-fast-path-" + workerId);
            workers.add(worker);
        }
        for (int i = 0; i < config.numLoadBalancers(); i++) {
            int loadBalancerId = i;
            Thread loadBalancer = new Thread(() -> runLoadBalancer(loadBalancerId,
                    loadBalancerQueues.get(loadBalancerId), workerQueues, workerFailure),
                    "dpi-load-balancer-" + loadBalancerId);
            loadBalancers.add(loadBalancer);
        }
        outputThread.start();
        workers.forEach(Thread::start);
        loadBalancers.forEach(Thread::start);

        try {
            RawPacket raw;
            int packetId = 0;
            while ((raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null || !parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    if (config.verbose()) System.err.println("[DPI] Skipped an unparseable or unsupported packet");
                    continue;
                }
                FiveTuple tuple = new FiveTuple(parseIp(parsed.srcIp), parseIp(parsed.destIp),
                        parsed.srcPort, parsed.destPort, parsed.protocol);
                PacketJob job = new PacketJob(packetId++, raw.header().timestampSeconds(),
                        raw.header().timestampFraction(), tuple, raw.data(), parsed.tcpFlags,
                        parsed.payloadOffset, parsed.payload.length);
                totalPackets.increment();
                totalBytes.add(raw.data().length);
                if (parsed.hasTcp) tcpPackets.increment();
                else udpPackets.increment();

                int loadBalancerId = Math.floorMod(tuple.hashCode(), config.numLoadBalancers());
                loadBalancerQueues.get(loadBalancerId).put(job);
            }
        } catch (IOException | InterruptedException exception) {
            if (exception instanceof InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw interrupted;
            }
            throw (IOException) exception;
        } finally {
            for (BlockingQueue<PacketJob> queue : loadBalancerQueues) queue.put(PacketJob.endOfStream());
            for (Thread loadBalancer : loadBalancers) {
                try {
                    loadBalancer.join();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw exception;
                }
            }
            for (BlockingQueue<PacketJob> queue : workerQueues) queue.put(PacketJob.endOfStream());
            for (Thread worker : workers) {
                try {
                    worker.join();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw exception;
                }
            }
            outputQueue.put(PacketJob.endOfStream());
            try {
                outputThread.join();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw exception;
            }
        }
        if (workerFailure.get() != null) throw workerFailure.get();
        if (outputFailure.get() != null) throw outputFailure.get();
    }

    private void runLoadBalancer(int loadBalancerId, BlockingQueue<PacketJob> input,
                                 List<BlockingQueue<PacketJob>> workerQueues,
                                 AtomicReference<IOException> workerFailure) {
        try {
            while (true) {
                PacketJob job = input.take();
                if (job.isEndOfStream()) return;
                loadBalancerCounts.get(loadBalancerId).increment();
                int workerOffset = loadBalancerId * config.fastPathsPerLoadBalancer();
                int workerWithinGroup = Math.floorMod(job.tuple().hashCode(),
                        config.fastPathsPerLoadBalancer());
                workerQueues.get(workerOffset + workerWithinGroup).put(job);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            workerFailure.compareAndSet(null, new IOException("Load-balancer thread interrupted", exception));
        }
    }

    private void runWorker(int workerId, BlockingQueue<PacketJob> input,
                           BlockingQueue<PacketJob> output, AtomicReference<IOException> workerFailure) {
        ConnectionTracker tracker = trackers.get(workerId);
        try {
            while (true) {
                PacketJob job = input.take();
                if (job.isEndOfStream()) return;
                try {
                    workerCounts.get(workerId).increment();
                    Connection connection = tracker.getOrCreateConnection(job.tuple());
                    tracker.updateConnection(connection, job.data().length, false);
                    synchronized (connection) {
                        if (connection.state != ConnectionState.BLOCKED
                                && connection.state != ConnectionState.CLOSED) {
                            inspect(job, connection, tracker);
                            RuleManager.BlockReason reason = ruleManager.shouldBlock(
                                    job.tuple().srcIp(), job.tuple().dstPort(),
                                    connection.appType, connection.sni);
                            if (reason != null) {
                                tracker.blockConnection(connection);
                                if (config.verbose()) {
                                    System.out.printf("[DPI] Dropped %s (%s: %s)%n",
                                            job.tuple(), reason.type(), reason.detail());
                                }
                            }
                            updateTcpState(connection, job.tcpFlags());
                        }
                        if (connection.action == PacketAction.DROP) {
                            droppedPackets.increment();
                        } else {
                            forwardedPackets.increment();
                            output.put(job);
                        }
                        appCounts.computeIfAbsent(connection.appType, ignored -> new LongAdder()).increment();
                        if (!connection.sni.isEmpty()) detectedDomains.put(connection.sni, connection.appType);
                        if (job.packetId() < 1000) {
                            packetViews.put(job.packetId(), new PacketView(job.packetId() + 1,
                                    ipToString(job.tuple().srcIp()), ipToString(job.tuple().dstIp()),
                                    job.tuple().srcPort(), job.tuple().dstPort(),
                                    job.tuple().protocol() == PacketParser.PROTOCOL_TCP ? "TCP" : "UDP",
                                    appTypeToString(connection.appType), connection.sni,
                                    connection.action == PacketAction.DROP ? "Blocked" : "Allowed",
                                    job.data().length));
                        }
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    workerFailure.compareAndSet(null, new IOException("Fast-path worker interrupted", exception));
                    return;
                } catch (RuntimeException exception) {
                    workerFailure.compareAndSet(null, new IOException("Fast-path worker failed", exception));
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            workerFailure.compareAndSet(null, new IOException("Fast-path worker interrupted", exception));
        }
    }

    private static void inspect(PacketJob job, Connection connection, ConnectionTracker tracker) {
        byte[] payload = job.data();
        int offset = job.payloadOffset();
        int length = job.payloadLength();
        if (offset < 0 || length < 0 || offset > payload.length || length > payload.length - offset) return;
        byte[] data = java.util.Arrays.copyOfRange(payload, offset, offset + length);
        AppType detected = AppType.UNKNOWN;
        String domain = "";

        if (job.tuple().protocol() == PacketParser.PROTOCOL_TCP && job.tuple().dstPort() == 443) {
            domain = SniExtractor.extractTlsServerName(data).orElse("");
            if (!domain.isEmpty()) detected = sniToAppType(domain);
            else if (connection.appType == AppType.UNKNOWN) detected = AppType.HTTPS;
        } else if (job.tuple().protocol() == PacketParser.PROTOCOL_TCP && job.tuple().dstPort() == 80) {
            domain = SniExtractor.extractHttpHost(data).orElse("");
            if (!domain.isEmpty()) detected = sniToAppType(domain);
            else if (connection.appType == AppType.UNKNOWN) detected = AppType.HTTP;
        } else if (job.tuple().dstPort() == 53 || job.tuple().srcPort() == 53) {
            if (job.tuple().srcPort() != 53) domain = SniExtractor.extractDnsQuery(data).orElse("");
            detected = domain.isEmpty() ? AppType.DNS : sniToAppType(domain);
            if (detected == AppType.UNKNOWN) detected = AppType.DNS;
        } else if (job.tuple().protocol() == PacketParser.PROTOCOL_UDP
                && (job.tuple().dstPort() == 443 || job.tuple().srcPort() == 443)
                && SniExtractor.isQuicInitial(data)) {
            detected = AppType.QUIC;
        }

        if (!domain.isEmpty()) {
            tracker.classifyConnection(connection, detected, domain);
        } else if (detected != AppType.UNKNOWN && detected != AppType.HTTP && detected != AppType.HTTPS) {
            tracker.classifyConnection(connection, detected, "");
        } else if (connection.appType == AppType.UNKNOWN && detected != AppType.UNKNOWN) {
            connection.appType = detected;
        }
    }

    private static void updateTcpState(Connection connection, int flags) {
        if ((flags & 0x02) != 0 && (flags & 0x10) == 0) {
            connection.synSeen = true;
            if (connection.state == ConnectionState.NEW) connection.state = ConnectionState.ESTABLISHED;
        }
        if ((flags & 0x12) == 0x12) connection.synAckSeen = true;
        if ((flags & 0x01) != 0 || (flags & 0x04) != 0) {
            connection.finSeen = true;
            connection.state = ConnectionState.CLOSED;
        }
    }

    private static void writeOutput(BlockingQueue<PacketJob> queue, DataOutputStream output,
                                    PcapGlobalHeader header, AtomicReference<IOException> failure) {
        boolean writeFailed = false;
        try {
            while (true) {
                PacketJob job = queue.take();
                if (job.isEndOfStream()) return;
                if (writeFailed) continue;
                ByteBuffer packetHeader = ByteBuffer.allocate(16).order(header.littleEndian()
                        ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
                packetHeader.putInt((int) job.timestampSeconds());
                packetHeader.putInt((int) job.timestampFraction());
                packetHeader.putInt(job.data().length);
                packetHeader.putInt(job.data().length);
                output.write(packetHeader.array());
                output.write(job.data());
            } 
        } catch (IOException exception) {
            failure.compareAndSet(null, exception);
            writeFailed = true;
            while (true) {
                try {
                    if (queue.take().isEndOfStream()) return;
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    failure.compareAndSet(null, new IOException("Output writer interrupted", interrupted));
                    return;
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failure.compareAndSet(null, new IOException("Output writer interrupted", exception));
        }
    }

    public ProcessingReport getProcessingReport() {
        Map<String, Long> apps = new java.util.TreeMap<>();
        appCounts.forEach((type, count) -> apps.put(appTypeToString(type), count.sum()));
        return new ProcessingReport(totalPackets.sum(), totalBytes.sum(), tcpPackets.sum(),
                udpPackets.sum(), forwardedPackets.sum(), droppedPackets.sum(),
                trackers.stream().mapToInt(ConnectionTracker::getActiveCount).sum(),
                trackers.stream().map(ConnectionTracker::getStats)
                        .mapToLong(ConnectionTracker.TrackerStats::totalConnectionsSeen).sum(),
                Map.copyOf(apps), packetViews.values().stream()
                        .sorted(Comparator.comparingInt(PacketView::packetNumber)).toList());
    }

    private void printReport(ProcessingReport report) {
        System.out.println("\nDPI ENGINE STATISTICS");
        System.out.println("Total packets: " + report.totalPackets());
        System.out.println("Total bytes: " + report.totalBytes());
        System.out.println("TCP packets: " + report.tcpPackets());
        System.out.println("UDP packets: " + report.udpPackets());
        System.out.println("Forwarded: " + report.forwardedPackets());
        System.out.println("Dropped/blocked: " + report.droppedPackets());
        if (report.totalPackets() > 0) {
            System.out.printf("Drop rate: %.2f%%%n",
                    100.0 * report.droppedPackets() / report.totalPackets());
        }
        for (int i = 0; i < loadBalancerCounts.size(); i++) {
            System.out.printf("LB%d dispatched: %d%n", i, loadBalancerCounts.get(i).sum());
        }
        for (int i = 0; i < workerCounts.size(); i++) {
            System.out.printf("FP%d processed: %d%n", i, workerCounts.get(i).sum());
        }
        System.out.println("APPLICATION BREAKDOWN");
        long appTotal = appCounts.values().stream().mapToLong(LongAdder::sum).sum();
        appCounts.entrySet().stream()
                .sorted((left, right) -> Long.compare(right.getValue().sum(), left.getValue().sum()))
                .forEach(entry -> System.out.printf("%-15s %8d %5.1f%%%n",
                        appTypeToString(entry.getKey()), entry.getValue().sum(),
                        appTotal == 0 ? 0.0 : 100.0 * entry.getValue().sum() / appTotal));
        if (!detectedDomains.isEmpty()) {
            System.out.println("Detected domains/SNIs");
            detectedDomains.forEach((domain, app) ->
                    System.out.printf("  %s -> %s%n", domain, appTypeToString(app)));
        }
        System.out.print(globalConnectionTable.generateReport());
        System.out.println("Rules: " + ruleManager.getStats());
    }
}
