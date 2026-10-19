package packetanalyzer;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

import static packetanalyzer.Models.*;

public final class WebMain {
    private static final int MAX_UPLOAD_BYTES = 64 * 1024 * 1024;
    private final int port;
    private final Path storageDirectory;
    private final Map<String, Path> downloads = new ConcurrentHashMap<>();

    private WebMain(int port) throws IOException {
        this.port = port;
        storageDirectory = Files.createTempDirectory("packet-analyzer-web-");
    }

    public static void main(String[] args) throws IOException {
        int port = 8765;
        if (args.length > 1 || (args.length == 1 && args[0].equals("--help"))) {
            System.err.println("Usage: java -cp build\\classes packetanalyzer.WebMain [port]");
            if (args.length == 1) return;
            System.exit(2);
        }
        if (args.length == 1) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Port must be a number between 1 and 65535", exception);
            }
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Port must be between 1 and 65535");
        }
        WebMain app = new WebMain(port);
        app.start();
    }

    private void start() throws IOException {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        HttpServer server = HttpServer.create(new InetSocketAddress(loopback, port), 0);
        server.createContext("/", this::servePage);
        server.createContext("/api/analyze", this::analyze);
        server.createContext("/api/download/", this::download);
        server.setExecutor(Executors.newFixedThreadPool(4, task -> {
            Thread thread = new Thread(task, "packet-analyzer-web");
            thread.setDaemon(true);
            return thread;
        }));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(1);
            try {
                deleteTemporaryFiles();
            } catch (IOException exception) {
                System.err.println("Could not clean temporary web files: " + exception.getMessage());
            }
        }));
        server.start();
        String address = loopback.getHostAddress();
        if (address.contains(":")) address = "[" + address + "]";
        System.out.println("Packet Analyzer is ready at http://" + address + ":" + port);
        System.out.println("This server only accepts connections from this computer. Press Ctrl+C to stop.");
    }

    private void servePage(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Only GET is supported for the dashboard");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        if (!path.equals("/") && !path.equals("/index.html")) {
            sendError(exchange, 404, "Page not found");
            return;
        }
        try (var resource = WebMain.class.getResourceAsStream("/packetanalyzer/index.html")) {
            if (resource == null) {
                sendError(exchange, 500, "Dashboard page is missing from the build");
                return;
            }
            byte[] page = resource.readAllBytes();
            setSecurityHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, page.length);
            exchange.getResponseBody().write(page);
        }
    }

    private void analyze(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            sendError(exchange, 405, "Use POST to analyze a PCAP file");
            return;
        }
        if (!isSameOrigin(exchange)) {
            sendError(exchange, 403, "Cross-origin requests are not allowed");
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("application/octet-stream")) {
            sendError(exchange, 415, "Upload the capture as application/octet-stream");
            return;
        }
        String contentLength = exchange.getRequestHeaders().getFirst("Content-Length");
        if (contentLength != null) {
            try {
                if (Long.parseLong(contentLength) > MAX_UPLOAD_BYTES) {
                    sendError(exchange, 413, "PCAP files must be 64 MB or smaller");
                    return;
                }
            } catch (NumberFormatException exception) {
                sendError(exchange, 400, "Invalid Content-Length");
                return;
            }
        }

        Path input = null;
        Path output = null;
        try {
            byte[] uploaded;
            try (var body = exchange.getRequestBody()) {
                uploaded = body.readNBytes(MAX_UPLOAD_BYTES + 1);
            }
            if (uploaded.length == 0) {
                sendError(exchange, 400, "Choose a PCAP file first");
                return;
            }
            if (uploaded.length > MAX_UPLOAD_BYTES) {
                sendError(exchange, 413, "PCAP files must be 64 MB or smaller");
                return;
            }
            input = Files.createTempFile(storageDirectory, "capture-", ".pcap");
            output = Files.createTempFile(storageDirectory, "filtered-", ".pcap");
            Files.write(input, uploaded);

            DpiEngine engine = new DpiEngine(DpiEngine.Config.defaults());
            Map<String, List<String>> options = parseQuery(exchange.getRequestURI());
            for (String ip : values(options, "ip")) engine.blockIp(ip);
            for (String app : values(options, "app")) engine.blockApp(app);
            for (String domain : values(options, "domain")) engine.blockDomain(domain);
            DpiEngine.ProcessingReport report = engine.processFile(input, output);
            String id = UUID.randomUUID().toString();
            downloads.put(id, output);
            output = null;
            sendJson(exchange, 200, reportJson(report, id));
        } catch (IllegalArgumentException exception) {
            sendError(exchange, 400, exception.getMessage());
        } catch (IOException exception) {
            System.err.println("PCAP analysis failed: " + exception.getMessage());
            sendError(exchange, 422, exception.getMessage());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            sendError(exchange, 500, "Analysis was interrupted");
        } finally {
            deleteQuietly(input);
            deleteQuietly(output);
        }
    }

    private void download(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendError(exchange, 405, "Use GET to download the filtered PCAP");
            return;
        }
        String prefix = "/api/download/";
        String path = exchange.getRequestURI().getPath();
        String id = path.startsWith(prefix) ? path.substring(prefix.length()) : "";
        Path file = downloads.get(id);
        if (file == null || !Files.isRegularFile(file)) {
            sendError(exchange, 404, "Download not found; analyze a capture again");
            return;
        }
        long length = Files.size(file);
        setSecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/vnd.tcpdump.pcap");
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"filtered.pcap\"");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, length);
        try (var input = Files.newInputStream(file); var response = exchange.getResponseBody()) {
            input.transferTo(response);
        }
    }

    private boolean isSameOrigin(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin == null) return true;
        try {
            URI uri = URI.create(origin);
            String host = uri.getHost();
            return uri.getPort() == port && ("localhost".equalsIgnoreCase(host)
                    || "127.0.0.1".equals(host) || "::1".equals(host)
                    || "0:0:0:0:0:0:0:1".equalsIgnoreCase(host));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static Map<String, List<String>> parseQuery(URI uri) {
        Map<String, List<String>> values = new HashMap<>();
        String query = uri.getRawQuery();
        if (query == null || query.isEmpty()) return values;
        for (String item : query.split("&")) {
            int separator = item.indexOf('=');
            String key = decode(separator < 0 ? item : item.substring(0, separator));
            String value = decode(separator < 0 ? "" : item.substring(separator + 1));
            values.computeIfAbsent(key, ignored -> new ArrayList<>()).add(value);
        }
        return values;
    }

    private static List<String> values(Map<String, List<String>> options, String key) {
        return options.getOrDefault(key, List.of()).stream()
                .flatMap(value -> java.util.Arrays.stream(value.split(",")))
                .map(String::trim).filter(value -> !value.isEmpty()).toList();
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String reportJson(DpiEngine.ProcessingReport report, String downloadId) {
        StringBuilder json = new StringBuilder("{\"totalPackets\":").append(report.totalPackets())
                .append(",\"totalBytes\":").append(report.totalBytes())
                .append(",\"tcpPackets\":").append(report.tcpPackets())
                .append(",\"udpPackets\":").append(report.udpPackets())
                .append(",\"forwardedPackets\":").append(report.forwardedPackets())
                .append(",\"droppedPackets\":").append(report.droppedPackets())
                .append(",\"activeConnections\":").append(report.activeConnections())
                .append(",\"totalConnectionsSeen\":").append(report.totalConnectionsSeen())
                .append(",\"downloadId\":\"").append(jsonEscape(downloadId)).append("\",\"applications\":{");
        boolean first = true;
        for (Map.Entry<String, Long> app : report.applicationDistribution().entrySet()) {
            if (!first) json.append(',');
            first = false;
            json.append('"').append(jsonEscape(app.getKey())).append("\":").append(app.getValue());
        }
        json.append("},\"packets\":[");
        first = true;
        for (DpiEngine.PacketView packet : report.packets()) {
            if (!first) json.append(',');
            first = false;
            json.append("{\"number\":").append(packet.packetNumber())
                    .append(",\"sourceIp\":\"").append(jsonEscape(packet.sourceIp()))
                    .append("\",\"destinationIp\":\"").append(jsonEscape(packet.destinationIp()))
                    .append("\",\"sourcePort\":").append(packet.sourcePort())
                    .append(",\"destinationPort\":").append(packet.destinationPort())
                    .append(",\"protocol\":\"").append(jsonEscape(packet.protocol()))
                    .append("\",\"application\":\"").append(jsonEscape(packet.application()))
                    .append("\",\"domain\":\"").append(jsonEscape(packet.domain()))
                    .append("\",\"verdict\":\"").append(jsonEscape(packet.verdict()))
                    .append("\",\"bytes\":").append(packet.bytes()).append('}');
        }
        return json.append("]}").toString();
    }

    private static String jsonEscape(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) escaped.append(String.format("\\u%04x", (int) character));
                    else escaped.append(character);
                }
            }
        }
        return escaped.toString();
    }

    private static void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendJson(exchange, status, "{\"error\":\"" + jsonEscape(message == null ? "Request failed" : message) + "\"}");
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        setSecurityHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, response.length);
        try (var body = exchange.getResponseBody()) {
            body.write(response);
        }
    }

    private static void setSecurityHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                        + "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    }

    private void deleteTemporaryFiles() throws IOException {
        try (var files = Files.list(storageDirectory)) {
            for (Path file : files.toList()) Files.deleteIfExists(file);
        }
        Files.deleteIfExists(storageDirectory);
    }

    private static void deleteQuietly(Path path) {
        if (path == null) return;
        try {
            Files.deleteIfExists(path);
        } catch (IOException exception) {
            System.err.println("Could not remove temporary file: " + exception.getMessage());
        }
    }
}
