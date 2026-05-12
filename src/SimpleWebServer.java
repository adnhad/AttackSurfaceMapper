import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.Executors;

public final class SimpleWebServer {
    private static final int DEFAULT_PORT = 8080;
    private static final Path WEB_ROOT = Path.of("web");

    private final HttpServer server;

    private SimpleWebServer(HttpServer server) {
        this.server = server;
    }

    public static SimpleWebServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/api/health", new HealthHandler());
        server.createContext("/api/analyze", new AnalyzeHandler());
        server.createContext("/", new StaticHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        return new SimpleWebServer(server);
    }

    public static int parsePort(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                return Integer.parseInt(args[i + 1]);
            }
        }
        return DEFAULT_PORT;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        server.stop(0);
    }

    private static final class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }
            sendJson(exchange, 200, "{\"ok\":true}");
        }
    }

    private static final class AnalyzeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method not allowed\"}");
                return;
            }

            String fileName = exchange.getRequestHeaders().getFirst("X-Filename");
            if (fileName == null || fileName.isBlank()) {
                sendJson(exchange, 400, "{\"error\":\"Missing X-Filename header\"}");
                return;
            }

            byte[] body;
            try (InputStream inputStream = exchange.getRequestBody()) {
                body = inputStream.readAllBytes();
            }
            if (body.length == 0) {
                sendJson(exchange, 400, "{\"error\":\"Empty upload\"}");
                return;
            }

            String safeName = sanitizeFileName(fileName);
            String suffix = safeName.contains(".")
                ? safeName.substring(safeName.lastIndexOf('.'))
                : ".bin";
            Path tempFile = Files.createTempFile("asm-upload-", suffix);

            try {
                Files.write(tempFile, body);
                AttackSurfaceReport report = AttackSurfaceAnalyzer.analyze(ManifestLoader.load(tempFile));
                String response = "{"
                    + "\"fileName\":\"" + escapeJson(fileName) + "\","
                    + "\"report\":" + report.toJson()
                    + "}";
                sendJson(exchange, 200, response);
            } catch (Exception exception) {
                String message = exception.getMessage() == null ? exception.toString() : exception.getMessage();
                sendJson(exchange, 500, "{\"error\":\"" + escapeJson(message) + "\"}");
            } finally {
                Files.deleteIfExists(tempFile);
            }
        }
    }

    private static final class StaticHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendText(exchange, 405, "Method not allowed", "text/plain; charset=utf-8");
                return;
            }

            URI requestUri = exchange.getRequestURI();
            String rawPath = requestUri.getPath();
            String normalized = rawPath.equals("/") ? "/index.html" : rawPath;
            Path requested = WEB_ROOT.resolve("." + normalized).normalize();

            if (!requested.startsWith(WEB_ROOT.normalize()) || Files.isDirectory(requested) || !Files.exists(requested)) {
                sendText(exchange, 404, "Not found", "text/plain; charset=utf-8");
                return;
            }

            byte[] content = Files.readAllBytes(requested);
            sendBytes(exchange, 200, content, contentType(requested));
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        sendBytes(exchange, status, json.getBytes(StandardCharsets.UTF_8), "application/json; charset=utf-8");
    }

    private static void sendText(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        sendBytes(exchange, status, body.getBytes(StandardCharsets.UTF_8), contentType);
    }

    private static void sendBytes(HttpExchange exchange, int status, byte[] bytes, String contentType) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static String contentType(Path path) {
        String lower = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html")) {
            return "text/html; charset=utf-8";
        }
        if (lower.endsWith(".css")) {
            return "text/css; charset=utf-8";
        }
        if (lower.endsWith(".js")) {
            return "application/javascript; charset=utf-8";
        }
        if (lower.endsWith(".json")) {
            return "application/json; charset=utf-8";
        }
        return "application/octet-stream";
    }

    private static String sanitizeFileName(String fileName) {
        return fileName.replace("\\", "_").replace("/", "_");
    }

    private static String escapeJson(String value) {
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n");
    }
}
