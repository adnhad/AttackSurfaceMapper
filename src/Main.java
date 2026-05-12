import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            startServer(new String[0]);
            return;
        }

        if ("serve".equalsIgnoreCase(args[0])) {
            startServer(args);
            return;
        }

        if (hasFlag(args, "--help") || hasFlag(args, "-h")) {
            printUsage();
            return;
        }

        Path input = Path.of(args[0]);
        if (!Files.exists(input)) {
            throw new IOException("Input not found: " + input);
        }

        AttackSurfaceModel model = ManifestLoader.load(input);
        AttackSurfaceReport report = AttackSurfaceAnalyzer.analyze(model);

        if (hasFlag(args, "--json")) {
            System.out.println(report.toJson());
            return;
        }

        System.out.println(report.toText());
    }

    private static void startServer(String[] args) throws Exception {
        int port = SimpleWebServer.parsePort(args);
        SimpleWebServer server = SimpleWebServer.start(port);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        System.out.println("Attack Surface Mapper UI running at http://127.0.0.1:" + server.port());
        System.out.println("Press Ctrl+C to stop.");
        new CountDownLatch(1).await();
    }

    private static boolean hasFlag(String[] args, String flag) {
        for (String arg : args) {
            if (flag.equalsIgnoreCase(arg)) {
                return true;
            }
        }
        return false;
    }

    private static void printUsage() {
        System.out.println("Attack Surface Mapper");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  New-Item -ItemType Directory -Force out | Out-Null");
        System.out.println("  javac -d out src\\*.java");
        System.out.println("  java -cp out Main");
        System.out.println("  java -cp out Main serve --port 8080");
        System.out.println("  java -cp out Main <AndroidManifest.xml|app.apk> [--json]");
        System.out.println();
        System.out.println("Outputs:");
        System.out.println("  - Web UI with drag-and-drop APK upload");
        System.out.println("  - Extracted Android attack surface");
        System.out.println("  - Risk score, explanations, recommendations, and Mermaid graph");
        System.out.println();
        System.out.println("Notes:");
        System.out.println("  - Run with a modern JDK because Android binary XML support relies on recent Java language features.");
        System.out.println("  - Plain XML manifests are supported.");
        System.out.println("  - APK files are supported through built-in Android binary XML parsing.");
    }
}
