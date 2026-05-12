import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class AttackSurfaceModel {
    public final String sourceName;
    public final String packageName;
    public final ApkMetadata apkMetadata;
    public final List<Component> components = new ArrayList<>();
    public final Set<String> usesPermissions = new LinkedHashSet<>();
    public boolean allowBackup;
    public boolean debuggable;
    public boolean fullBackupOnly;
    public String backupAgent = "";

    public AttackSurfaceModel(String sourceName, String packageName, ApkMetadata apkMetadata) {
        this.sourceName = sourceName;
        this.packageName = packageName;
        this.apkMetadata = apkMetadata;
    }

    public enum ComponentType {
        ACTIVITY,
        ACTIVITY_ALIAS,
        SERVICE,
        RECEIVER,
        PROVIDER
    }

    public static class Component {
        public ComponentType type;
        public String name = "";
        public boolean exported;
        public boolean exportedDefined;
        public String permission = "";
        public String readPermission = "";
        public String writePermission = "";
        public String taskAffinity = "";
        public boolean grantUriPermissions;
        public int pathPermissions;
        public int grantUriPermissionPatterns;
        public List<String> authorities = new ArrayList<>();
        public final List<IntentFilter> intentFilters = new ArrayList<>();
    }

    public static class IntentFilter {
        public final Set<String> actions = new LinkedHashSet<>();
        public final Set<String> categories = new LinkedHashSet<>();
        public final List<DataSpec> dataSpecs = new ArrayList<>();
        public boolean autoVerify;
    }

    public static class DataSpec {
        public String scheme = "";
        public String host = "";
        public String port = "";
        public String path = "";
        public String pathPrefix = "";
        public String pathPattern = "";
        public String mimeType = "";

        public boolean isDeepLink() {
            return !scheme.isEmpty() || !host.isEmpty() || !mimeType.isEmpty();
        }

        public String toShortString() {
            StringBuilder builder = new StringBuilder();
            if (!scheme.isEmpty()) {
                builder.append(scheme).append("://");
            }
            if (!host.isEmpty()) {
                builder.append(host);
            }
            if (!port.isEmpty()) {
                builder.append(':').append(port);
            }
            if (!path.isEmpty()) {
                builder.append(path);
            } else if (!pathPrefix.isEmpty()) {
                builder.append(pathPrefix).append('*');
            } else if (!pathPattern.isEmpty()) {
                builder.append(pathPattern);
            }
            if (!mimeType.isEmpty()) {
                if (builder.length() > 0) {
                    builder.append(' ');
                }
                builder.append('(').append(mimeType).append(')');
            }
            return builder.toString();
        }
    }
}
