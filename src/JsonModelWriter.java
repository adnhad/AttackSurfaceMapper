import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class JsonModelWriter {
    private JsonModelWriter() {
    }

    public static String componentsToJson(List<AttackSurfaceModel.Component> components) {
        return "[" + components.stream().map(JsonModelWriter::componentToJson).collect(Collectors.joining(",")) + "]";
    }

    public static String stringsToJson(Set<String> values) {
        return "[" + values.stream().map(value -> "\"" + escape(value) + "\"").collect(Collectors.joining(",")) + "]";
    }

    private static String componentToJson(AttackSurfaceModel.Component component) {
        String filters = component.intentFilters.stream()
            .map(JsonModelWriter::filterToJson)
            .collect(Collectors.joining(","));
        return "{"
            + "\"type\":\"" + escape(component.type.name()) + "\","
            + "\"name\":\"" + escape(component.name) + "\","
            + "\"exported\":" + component.exported + ","
            + "\"exportedDefined\":" + component.exportedDefined + ","
            + "\"permission\":\"" + escape(component.permission) + "\","
            + "\"readPermission\":\"" + escape(component.readPermission) + "\","
            + "\"writePermission\":\"" + escape(component.writePermission) + "\","
            + "\"grantUriPermissions\":" + component.grantUriPermissions + ","
            + "\"pathPermissions\":" + component.pathPermissions + ","
            + "\"grantUriPermissionPatterns\":" + component.grantUriPermissionPatterns + ","
            + "\"authorities\":[" + component.authorities.stream().map(a -> "\"" + escape(a) + "\"").collect(Collectors.joining(",")) + "],"
            + "\"intentFilters\":[" + filters + "]"
            + "}";
    }

    private static String filterToJson(AttackSurfaceModel.IntentFilter filter) {
        String actions = filter.actions.stream().map(a -> "\"" + escape(a) + "\"").collect(Collectors.joining(","));
        String categories = filter.categories.stream().map(c -> "\"" + escape(c) + "\"").collect(Collectors.joining(","));
        String dataSpecs = filter.dataSpecs.stream().map(JsonModelWriter::dataSpecToJson).collect(Collectors.joining(","));
        return "{"
            + "\"autoVerify\":" + filter.autoVerify + ","
            + "\"actions\":[" + actions + "],"
            + "\"categories\":[" + categories + "],"
            + "\"dataSpecs\":[" + dataSpecs + "]"
            + "}";
    }

    private static String dataSpecToJson(AttackSurfaceModel.DataSpec dataSpec) {
        return "{"
            + "\"scheme\":\"" + escape(dataSpec.scheme) + "\","
            + "\"host\":\"" + escape(dataSpec.host) + "\","
            + "\"port\":\"" + escape(dataSpec.port) + "\","
            + "\"path\":\"" + escape(dataSpec.path) + "\","
            + "\"pathPrefix\":\"" + escape(dataSpec.pathPrefix) + "\","
            + "\"pathPattern\":\"" + escape(dataSpec.pathPattern) + "\","
            + "\"mimeType\":\"" + escape(dataSpec.mimeType) + "\""
            + "}";
    }

    private static String escape(String value) {
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\r", "\\r")
            .replace("\n", "\\n");
    }
}
