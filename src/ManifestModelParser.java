import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class ManifestModelParser {
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    private ManifestModelParser() {
    }

    public static AttackSurfaceModel fromDocument(Document document, String sourceName, ApkMetadata apkMetadata) {
        Element manifest = document.getDocumentElement();
        String packageName = manifest.getAttribute("package");
        AttackSurfaceModel model = new AttackSurfaceModel(sourceName, packageName, apkMetadata);

        collectUsesPermissions(manifest, model);

        Element application = firstChild(manifest, "application");
        if (application != null) {
            model.allowBackup = readBoolean(application, "allowBackup", false);
            model.debuggable = readBoolean(application, "debuggable", false);
            model.fullBackupOnly = readBoolean(application, "fullBackupOnly", false);
            model.backupAgent = readAttr(application, "backupAgent");
            collectComponents(application, "activity", AttackSurfaceModel.ComponentType.ACTIVITY, model, packageName);
            collectComponents(application, "activity-alias", AttackSurfaceModel.ComponentType.ACTIVITY_ALIAS, model, packageName);
            collectComponents(application, "service", AttackSurfaceModel.ComponentType.SERVICE, model, packageName);
            collectComponents(application, "receiver", AttackSurfaceModel.ComponentType.RECEIVER, model, packageName);
            collectComponents(application, "provider", AttackSurfaceModel.ComponentType.PROVIDER, model, packageName);
        }

        return model;
    }

    private static void collectUsesPermissions(Element manifest, AttackSurfaceModel model) {
        NodeList children = manifest.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (!(node instanceof Element element)) {
                continue;
            }
            String tag = element.getTagName();
            if ("uses-permission".equals(tag) || "uses-permission-sdk-23".equals(tag) || "permission".equals(tag)) {
                String permission = readAttr(element, "name");
                if (!permission.isEmpty()) {
                    model.usesPermissions.add(permission);
                }
            }
        }
    }

    private static void collectComponents(Element application, String tagName, AttackSurfaceModel.ComponentType type,
                                          AttackSurfaceModel model, String packageName) {
        NodeList nodes = application.getElementsByTagName(tagName);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (!(node instanceof Element element) || node.getParentNode() != application) {
                continue;
            }

            AttackSurfaceModel.Component component = new AttackSurfaceModel.Component();
            component.type = type;
            component.name = normalizeComponentName(readAttr(element, "name"), packageName);
            component.permission = readAttr(element, "permission");
            component.readPermission = readAttr(element, "readPermission");
            component.writePermission = readAttr(element, "writePermission");
            component.taskAffinity = readAttr(element, "taskAffinity");
            component.grantUriPermissions = readBoolean(element, "grantUriPermissions", false);
            component.exportedDefined = hasAttr(element, "exported");
            component.exported = inferExported(element);
            component.authorities = splitCsv(readAttr(element, "authorities"));

            collectIntentFilters(element, component);
            collectMetaFlags(element, component);
            model.components.add(component);
        }
    }

    private static void collectMetaFlags(Element element, AttackSurfaceModel.Component component) {
        NodeList pathPermissions = element.getElementsByTagName("path-permission");
        component.pathPermissions = pathPermissions.getLength();

        NodeList grantNodes = element.getElementsByTagName("grant-uri-permission");
        component.grantUriPermissionPatterns = grantNodes.getLength();
    }

    private static void collectIntentFilters(Element element, AttackSurfaceModel.Component component) {
        NodeList filters = element.getElementsByTagName("intent-filter");
        for (int i = 0; i < filters.getLength(); i++) {
            Node node = filters.item(i);
            if (!(node instanceof Element filterElement) || node.getParentNode() != element) {
                continue;
            }
            AttackSurfaceModel.IntentFilter intentFilter = new AttackSurfaceModel.IntentFilter();
            intentFilter.autoVerify = readBoolean(filterElement, "autoVerify", false);

            NodeList entries = filterElement.getChildNodes();
            for (int j = 0; j < entries.getLength(); j++) {
                Node entry = entries.item(j);
                if (!(entry instanceof Element child)) {
                    continue;
                }
                switch (child.getTagName()) {
                    case "action" -> addIfNotEmpty(intentFilter.actions, readAttr(child, "name"));
                    case "category" -> addIfNotEmpty(intentFilter.categories, readAttr(child, "name"));
                    case "data" -> intentFilter.dataSpecs.add(readDataSpec(child));
                    default -> {
                    }
                }
            }
            component.intentFilters.add(intentFilter);
        }
    }

    private static AttackSurfaceModel.DataSpec readDataSpec(Element data) {
        AttackSurfaceModel.DataSpec spec = new AttackSurfaceModel.DataSpec();
        spec.scheme = readAttr(data, "scheme");
        spec.host = readAttr(data, "host");
        spec.port = readAttr(data, "port");
        spec.path = readAttr(data, "path");
        spec.pathPrefix = readAttr(data, "pathPrefix");
        spec.pathPattern = readAttr(data, "pathPattern");
        spec.mimeType = readAttr(data, "mimeType");
        return spec;
    }

    private static boolean inferExported(Element element) {
        if (hasAttr(element, "exported")) {
            return readBoolean(element, "exported", false);
        }
        return element.getElementsByTagName("intent-filter").getLength() > 0;
    }

    private static Element firstChild(Element parent, String tagName) {
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node instanceof Element element && tagName.equals(element.getTagName())) {
                return element;
            }
        }
        return null;
    }

    private static String normalizeComponentName(String name, String packageName) {
        if (name == null || name.isEmpty()) {
            return "";
        }
        if (name.startsWith(".")) {
            return packageName + name;
        }
        if (!name.contains(".") && !packageName.isEmpty()) {
            return packageName + "." + name;
        }
        return name;
    }

    private static List<String> splitCsv(String value) {
        List<String> values = new ArrayList<>();
        if (value == null || value.isBlank()) {
            return values;
        }
        for (String part : value.split(";")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static void addIfNotEmpty(Set<String> set, String value) {
        if (value != null && !value.isEmpty()) {
            set.add(value);
        }
    }

    private static String readAttr(Element element, String localName) {
        String namespaced = element.getAttributeNS(ANDROID_NS, localName);
        if (namespaced != null && !namespaced.isEmpty()) {
            return namespaced;
        }
        String prefixed = element.getAttribute("android:" + localName);
        if (prefixed != null && !prefixed.isEmpty()) {
            return prefixed;
        }
        return element.getAttribute(localName);
    }

    private static boolean hasAttr(Element element, String localName) {
        return element.hasAttributeNS(ANDROID_NS, localName)
            || element.hasAttribute("android:" + localName)
            || element.hasAttribute(localName);
    }

    private static boolean readBoolean(Element element, String localName, boolean defaultValue) {
        String value = readAttr(element, localName);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }
}
