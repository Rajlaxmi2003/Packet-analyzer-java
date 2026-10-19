package packetanalyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class DpiMain {
    private DpiMain() {}

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException | IOException exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            System.err.println("Error: DPI processing was interrupted");
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException, InterruptedException {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printUsage();
            return;
        }
        if (args.length < 2) {
            printUsage();
            throw new IllegalArgumentException("Both input and output PCAP paths are required");
        }

        int loadBalancers = 2;
        int fastPathsPerLoadBalancer = 2;
        int queueSize = 10_000;
        boolean verbose = false;
        Path rulesFile = null;
        List<String> blockedIps = new ArrayList<>();
        List<String> blockedApps = new ArrayList<>();
        List<String> blockedDomains = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--block-ip" -> blockedIps.add(requireValue(args, ++i, option));
                case "--block-app" -> blockedApps.add(requireValue(args, ++i, option));
                case "--block-domain" -> blockedDomains.add(requireValue(args, ++i, option));
                case "--rules" -> rulesFile = Path.of(requireValue(args, ++i, option));
                case "--lbs" -> loadBalancers = positiveInt(requireValue(args, ++i, option), option);
                case "--fps" -> fastPathsPerLoadBalancer = positiveInt(requireValue(args, ++i, option), option);
                case "--queue-size" -> queueSize = positiveInt(requireValue(args, ++i, option), option);
                case "--verbose" -> verbose = true;
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }

        DpiEngine engine = new DpiEngine(new DpiEngine.Config(loadBalancers,
                fastPathsPerLoadBalancer, queueSize, verbose));
        if (rulesFile != null) engine.loadRules(rulesFile);
        for (String ip : blockedIps) engine.blockIp(ip);
        for (String app : blockedApps) engine.blockApp(app);
        for (String domain : blockedDomains) engine.blockDomain(domain);
        engine.processFile(Path.of(args[0]), Path.of(args[1]));
        System.out.println("\nProcessing complete. Output written to: " + args[1]);
    }

    private static String requireValue(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException("Missing value for " + option);
        return args[index];
    }

    private static int positiveInt(String value, String option) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed > 0) return parsed;
        } catch (NumberFormatException ignored) {
            throw new IllegalArgumentException("Invalid positive integer for " + option + ": " + value);
        }
        throw new IllegalArgumentException("Invalid positive integer for " + option + ": " + value);
    }

    private static void printUsage() {
        System.out.println("""
                DPI Engine - Java Deep Packet Inspection

                Usage: java -cp build/classes packetanalyzer.DpiMain <input.pcap> <output.pcap> [options]

                Options:
                  --block-ip <ip>        Block packets from source IPv4 address
                  --block-app <app>      Block an application (YouTube, Facebook, etc.)
                  --block-domain <name>  Block a domain (wildcards such as *.example.com)
                  --rules <file>         Load rules from a rules file
                  --lbs <n>              Number of load-balancer groups (default: 2)
                  --fps <n>              Fast-path workers per group (default: 2)
                  --queue-size <n>       Bounded queue capacity (default: 10000)
                  --verbose              Print packet and rule details
                  --help                 Show this help
                """);
    }
}
