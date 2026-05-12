import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ApkMetadata {
    public final Set<String> entries = new LinkedHashSet<>();
    public boolean hasNetworkSecurityConfig;
    public boolean hasAssetLinks;
    public final Set<String> nativeLibraries = new LinkedHashSet<>();
    public final Set<String> dexFiles = new LinkedHashSet<>();
    public final Set<String> providerPathFiles = new LinkedHashSet<>();

    public static ApkMetadata fromZip(ZipFile zipFile) {
        ApkMetadata metadata = new ApkMetadata();
        Enumeration<? extends ZipEntry> enumeration = zipFile.entries();
        while (enumeration.hasMoreElements()) {
            ZipEntry entry = enumeration.nextElement();
            String name = entry.getName();
            metadata.entries.add(name);
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                metadata.nativeLibraries.add(name);
            }
            if (name.matches("classes(\\d+)?\\.dex")) {
                metadata.dexFiles.add(name);
            }
            if (name.endsWith("network_security_config.xml")) {
                metadata.hasNetworkSecurityConfig = true;
            }
            if (name.endsWith("assetlinks.json")) {
                metadata.hasAssetLinks = true;
            }
            if (name.endsWith("_paths.xml") || name.contains("/xml/") && name.contains("path")) {
                metadata.providerPathFiles.add(name);
            }
        }
        return metadata;
    }
}
