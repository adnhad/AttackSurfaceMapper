import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class AttackSurfaceReport {
    private final AttackSurfaceModel model;
    private final int riskScore;
    private final List<Finding> findings;
    private final String mermaidGraph;

    public record Finding(String severity, String title, String whyRisky, String remediation) {
    }

    public AttackSurfaceReport(AttackSurfaceModel model, int riskScore, List<Finding> findings, String mermaidGraph) {
        this.model = model;
        this.riskScore = riskScore;
        this.findings = findings;
        this.mermaidGraph = mermaidGraph;
    }

    public AttackSurfaceModel model() {
        return model;
    }

    public int riskScore() {
        return riskScore;
    }

    public String riskLevel() {
        if (riskScore >= 75) {
            return "HIGH";
        }
        if (riskScore >= 40) {
            return "MEDIUM";
        }
        return "LOW";
    }

    public List<Finding> findings() {
        return findings;
    }

    public String mermaidGraph() {
        return mermaidGraph;
    }

    public List<String> recommendations() {
        Set<String> unique = new LinkedHashSet<>();
        for (Finding finding : findings) {
            unique.add(finding.remediation());
        }
        return List.copyOf(unique);
    }

    public String toText() {
        StringBuilder builder = new StringBuilder();
        builder.append("Attack Surface Mapper").append('\n');
        builder.append("Source: ").append(model.sourceName).append('\n');
        if (!model.packageName.isEmpty()) {
            builder.append("Package: ").append(model.packageName).append('\n');
        }
        builder.append("Surface risk score: ").append(riskScore).append("/100").append('\n');
        builder.append('\n');

        builder.append("Components").append('\n');
        for (AttackSurfaceModel.Component component : model.components) {
            builder.append("- ")
                .append(component.type)
                .append(" | ")
                .append(component.name)
                .append(" | exported=")
                .append(component.exported);
            if (!component.permission.isEmpty()) {
                builder.append(" | permission=").append(component.permission);
            }
            if (!component.readPermission.isEmpty()) {
                builder.append(" | readPermission=").append(component.readPermission);
            }
            if (!component.writePermission.isEmpty()) {
                builder.append(" | writePermission=").append(component.writePermission);
            }
            builder.append('\n');

            for (AttackSurfaceModel.IntentFilter filter : component.intentFilters) {
                if (!filter.actions.isEmpty()) {
                    builder.append("    actions: ").append(String.join(", ", filter.actions)).append('\n');
                }
                if (!filter.categories.isEmpty()) {
                    builder.append("    categories: ").append(String.join(", ", filter.categories)).append('\n');
                }
                for (AttackSurfaceModel.DataSpec spec : filter.dataSpecs) {
                    builder.append("    data: ").append(spec.toShortString()).append('\n');
                }
            }
        }

        builder.append('\n');
        builder.append("Findings").append('\n');
        if (findings.isEmpty()) {
            builder.append("- No obvious high-signal attack surface issue detected from the available manifest/APK metadata.").append('\n');
        } else {
            for (Finding finding : findings) {
                builder.append("- [").append(finding.severity()).append("] ").append(finding.title()).append('\n');
                builder.append("  Why: ").append(finding.whyRisky()).append('\n');
                builder.append("  Fix: ").append(finding.remediation()).append('\n');
            }
        }

        builder.append('\n');
        builder.append("Mermaid Graph").append('\n');
        builder.append("```mermaid").append('\n');
        builder.append(mermaidGraph).append('\n');
        builder.append("```").append('\n');

        return builder.toString();
    }

    public String toJson() {
        String findingsJson = findings.stream()
            .map(finding -> "{"
                + "\"severity\":\"" + escape(finding.severity()) + "\","
                + "\"title\":\"" + escape(finding.title()) + "\","
                + "\"whyRisky\":\"" + escape(finding.whyRisky()) + "\","
                + "\"remediation\":\"" + escape(finding.remediation()) + "\""
                + "}")
            .collect(Collectors.joining(","));

        return "{"
            + "\"source\":\"" + escape(model.sourceName) + "\","
            + "\"package\":\"" + escape(model.packageName) + "\","
            + "\"riskScore\":" + riskScore + ","
            + "\"riskLevel\":\"" + riskLevel() + "\","
            + "\"components\":" + JsonModelWriter.componentsToJson(model.components) + ","
            + "\"findings\":[" + findingsJson + "],"
            + "\"recommendations\":[" + recommendations().stream()
                .map(value -> "\"" + escape(value) + "\"")
                .collect(Collectors.joining(",")) + "],"
            + "\"mermaid\":\"" + escape(mermaidGraph) + "\""
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
