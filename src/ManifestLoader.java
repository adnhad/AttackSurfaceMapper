import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ManifestLoader {
    private ManifestLoader() {
    }

    public static AttackSurfaceModel load(Path input) throws Exception {
        String fileName = input.getFileName().toString().toLowerCase();
        if (fileName.endsWith(".apk")) {
            return loadFromApk(input);
        }
        if (fileName.endsWith(".xml")) {
            return loadFromXml(input);
        }
        throw new IOException("Unsupported input type: " + input);
    }

    private static AttackSurfaceModel loadFromXml(Path xmlPath) throws Exception {
        byte[] xmlBytes = Files.readAllBytes(xmlPath);
        Document document = parseXml(xmlBytes);
        return ManifestModelParser.fromDocument(document, xmlPath.toString(), null);
    }

    private static AttackSurfaceModel loadFromApk(Path apkPath) throws Exception {
        try (ZipFile zipFile = new ZipFile(apkPath.toFile())) {
            ZipEntry manifestEntry = zipFile.getEntry("AndroidManifest.xml");
            if (manifestEntry == null) {
                throw new IOException("APK does not contain AndroidManifest.xml");
            }

            byte[] manifestBytes;
            try (InputStream inputStream = zipFile.getInputStream(manifestEntry)) {
                manifestBytes = inputStream.readAllBytes();
            }

            byte[] xmlBytes = BinaryXmlParser.isBinaryXml(manifestBytes)
                ? BinaryXmlParser.decodeToUtf8(manifestBytes)
                : manifestBytes;

            Document document = parseXml(xmlBytes);
            ApkMetadata apkMetadata = ApkMetadata.fromZip(zipFile);
            return ManifestModelParser.fromDocument(document, apkPath.toString(), apkMetadata);
        }
    }

    private static Document parseXml(byte[] xmlBytes) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setExpandEntityReferences(false);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlBytes)) {
            return factory.newDocumentBuilder().parse(inputStream);
        }
    }
}
