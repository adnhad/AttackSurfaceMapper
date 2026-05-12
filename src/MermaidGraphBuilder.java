import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class MermaidGraphBuilder {
    private MermaidGraphBuilder() {
    }

    public static String build(AttackSurfaceModel model) {
        StringBuilder builder = new StringBuilder();
        builder.append("flowchart LR\n");
        builder.append("    classDef component fill:#ffe8dc,stroke:#d95d39,stroke-width:2px,color:#1d2430;\n");
        builder.append("    classDef permission fill:#fff4d6,stroke:#d28b11,stroke-width:1.5px,color:#4b3403;\n");
        builder.append("    classDef intent fill:#e7f2ff,stroke:#4a78b8,stroke-width:1.5px,color:#17324d;\n");
        builder.append("    classDef data fill:#e9f8ef,stroke:#2c7a5b,stroke-width:1.5px,color:#164734;\n");
        builder.append("    classDef exposure fill:#fde4e1,stroke:#c6492d,stroke-width:1.5px,color:#6f1d12;\n");

        Map<AttackSurfaceModel.ComponentType, List<AttackSurfaceModel.Component>> grouped = groupComponents(model.components);
        Map<String, String> externalNodes = new LinkedHashMap<>();
        List<String> edges = new ArrayList<>();
        Map<String, Integer> ids = new LinkedHashMap<>();

        for (Map.Entry<AttackSurfaceModel.ComponentType, List<AttackSurfaceModel.Component>> entry : grouped.entrySet()) {
            builder.append("    subgraph ")
                .append(sectionId(entry.getKey()))
                .append("[\"")
                .append(sectionLabel(entry.getKey()))
                .append("\"]\n");

            for (AttackSurfaceModel.Component component : entry.getValue()) {
                String componentId = uniqueId(ids, "component_" + slug(component.type.name() + "_" + component.name));
                String label = component.type + "<br/>" + escape(component.name) + "<br/>exported: " + component.exported;
                builder.append("        ").append(componentId).append("[\"").append(label).append("\"]:::component\n");

                if (component.exported) {
                    String exposureId = uniqueId(ids, componentId + "_exported");
                    externalNodes.put(exposureId, "    " + exposureId + "((\"exported\")):::exposure");
                    edges.add("    " + componentId + " --> " + exposureId);
                }

                addPermissionNode(component.permission, "permission", componentId, ids, externalNodes, edges);
                addPermissionNode(component.readPermission, "read permission", componentId, ids, externalNodes, edges);
                addPermissionNode(component.writePermission, "write permission", componentId, ids, externalNodes, edges);

                for (int i = 0; i < component.intentFilters.size(); i++) {
                    AttackSurfaceModel.IntentFilter filter = component.intentFilters.get(i);
                    String filterId = uniqueId(ids, componentId + "_intent_filter_" + (i + 1));
                    externalNodes.put(filterId, "    " + filterId + "([\"" + formatIntentFilter(filter, i + 1) + "\"]):::intent");
                    edges.add("    " + componentId + " --> " + filterId);

                    String deepLinkSummary = summarizeDataSpecs(filter.dataSpecs);
                    if (!deepLinkSummary.isEmpty()) {
                        String dataId = uniqueId(ids, filterId + "_deep_link");
                        externalNodes.put(dataId, "    " + dataId + "[/\"deep link<br/>" + escape(deepLinkSummary) + "\"/]:::data");
                        edges.add("    " + filterId + " --> " + dataId);
                    }
                }
            }

            builder.append("    end\n");
        }

        for (String node : externalNodes.values()) {
            builder.append(node).append('\n');
        }
        for (String edge : edges) {
            builder.append(edge).append('\n');
        }

        return builder.toString().trim();
    }

    private static void addPermissionNode(String permission, String labelPrefix, String componentId,
                                          Map<String, Integer> ids, Map<String, String> externalNodes, List<String> edges) {
        if (permission == null || permission.isEmpty()) {
            return;
        }
        String permissionId = uniqueId(ids, labelPrefix.replace(' ', '_') + "_" + slug(permission));
        externalNodes.put(permissionId,
            "    " + permissionId + "{{\"" + labelPrefix + "<br/>" + escape(permission) + "\"}}:::permission");
        edges.add("    " + componentId + " --> " + permissionId);
    }

    private static String formatIntentFilter(AttackSurfaceModel.IntentFilter filter, int index) {
        List<String> parts = new ArrayList<>();
        parts.add("intent filter " + index);
        if (!filter.actions.isEmpty()) {
            parts.add("actions: " + String.join(", ", filter.actions));
        }
        if (!filter.categories.isEmpty()) {
            parts.add("categories: " + String.join(", ", filter.categories));
        }
        return escape(String.join("<br/>", parts));
    }

    private static String summarizeDataSpecs(List<AttackSurfaceModel.DataSpec> dataSpecs) {
        List<String> summaries = new ArrayList<>();
        for (AttackSurfaceModel.DataSpec dataSpec : dataSpecs) {
            String summary = dataSpec.toShortString();
            if (!summary.isEmpty()) {
                summaries.add(summary);
            }
        }
        return String.join("<br/>", summaries);
    }

    private static Map<AttackSurfaceModel.ComponentType, List<AttackSurfaceModel.Component>> groupComponents(List<AttackSurfaceModel.Component> components) {
        Map<AttackSurfaceModel.ComponentType, List<AttackSurfaceModel.Component>> grouped = new LinkedHashMap<>();
        for (AttackSurfaceModel.Component component : components) {
            grouped.computeIfAbsent(component.type, ignored -> new ArrayList<>()).add(component);
        }
        return grouped;
    }

    private static String sectionId(AttackSurfaceModel.ComponentType type) {
        return "section_" + slug(type.name());
    }

    private static String sectionLabel(AttackSurfaceModel.ComponentType type) {
        return switch (type) {
            case ACTIVITY -> "Activities";
            case ACTIVITY_ALIAS -> "Activity Aliases";
            case SERVICE -> "Services";
            case RECEIVER -> "Receivers";
            case PROVIDER -> "Providers";
        };
    }

    private static String uniqueId(Map<String, Integer> ids, String base) {
        int count = ids.getOrDefault(base, 0);
        ids.put(base, count + 1);
        return count == 0 ? base : base + "_" + (count + 1);
    }

    private static String slug(String value) {
        String normalized = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_");
        normalized = normalized.replaceAll("^_+|_+$", "");
        return normalized.isEmpty() ? "node" : normalized;
    }

    private static String escape(String value) {
        return value.replace("\"", "\\\"");
    }
}
