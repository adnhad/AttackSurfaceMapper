import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AttackSurfaceAnalyzer {
    private AttackSurfaceAnalyzer() {
    }

    public static AttackSurfaceReport analyze(AttackSurfaceModel model) {
        List<AttackSurfaceReport.Finding> findings = new ArrayList<>();
        int score = 0;

        if (model.allowBackup) {
            score += 12;
            findings.add(new AttackSurfaceReport.Finding(
                "MEDIUM",
                "Application backup is enabled",
                "android:allowBackup=\"true\" can expose app data through ADB or device migration flows on permissive devices.",
                "Disable backups with android:allowBackup=\"false\" unless business requirements need it, then scope backup data carefully."
            ));
        }

        if (model.debuggable) {
            score += 25;
            findings.add(new AttackSurfaceReport.Finding(
                "HIGH",
                "Application is debuggable",
                "android:debuggable=\"true\" increases runtime attack surface and can expose internals on production builds.",
                "Ensure release builds set android:debuggable=\"false\" and verify build variants do not override it."
            ));
        }

        for (AttackSurfaceModel.Component component : model.components) {
            score += componentScore(component);
            addComponentFindings(component, findings, model);
        }

        score = Math.min(score, 100);
        findings.sort(Comparator.comparingInt(AttackSurfaceAnalyzer::severityRank).reversed());
        return new AttackSurfaceReport(model, score, findings, MermaidGraphBuilder.build(model));
    }

    private static void addComponentFindings(AttackSurfaceModel.Component component,
                                             List<AttackSurfaceReport.Finding> findings,
                                             AttackSurfaceModel model) {
        if (component.exported && component.permission.isEmpty()
            && component.readPermission.isEmpty() && component.writePermission.isEmpty()) {
            findings.add(new AttackSurfaceReport.Finding(
                component.type == AttackSurfaceModel.ComponentType.PROVIDER ? "HIGH" : "MEDIUM",
                component.type + " exported without protection: " + component.name,
                "The component is reachable by other apps and no permission gate is declared.",
                "Set android:exported=\"false\" if external access is unnecessary, or protect the component with a signature-level permission."
            ));
        }

        boolean hasBrowsable = component.intentFilters.stream()
            .anyMatch(filter -> filter.categories.contains("android.intent.category.BROWSABLE"));
        boolean hasDeepLink = component.intentFilters.stream()
            .flatMap(filter -> filter.dataSpecs.stream())
            .anyMatch(AttackSurfaceModel.DataSpec::isDeepLink);
        if (component.exported && hasBrowsable && hasDeepLink) {
            findings.add(new AttackSurfaceReport.Finding(
                "MEDIUM",
                "Browsable deep link exposed: " + component.name,
                "Browsable components accept data from outside the app, which expands phishing and input-handling risk.",
                "Validate all incoming URI data, minimize accepted hosts and paths, and remove BROWSABLE when not strictly needed."
            ));
        }

        if (component.type == AttackSurfaceModel.ComponentType.PROVIDER && component.exported) {
            if (component.authorities.isEmpty()) {
                findings.add(new AttackSurfaceReport.Finding(
                    "MEDIUM",
                    "Exported provider with unclear authorities: " + component.name,
                    "An exported provider should clearly scope its authorities to avoid accidental data exposure.",
                    "Define a specific authority, review all public URIs, and require permissions for sensitive reads or writes."
                ));
            }

            if (component.grantUriPermissions && component.pathPermissions == 0 && component.grantUriPermissionPatterns == 0) {
                findings.add(new AttackSurfaceReport.Finding(
                    "HIGH",
                    "Broad URI grants on provider: " + component.name,
                    "grantUriPermissions is enabled without additional path constraints, which can widen shared-data exposure.",
                    "Restrict granted paths with path-permission or grant-uri-permission entries, or disable URI grants."
                ));
            }

            boolean looksLikeFileProvider = component.name.toLowerCase(Locale.ROOT).contains("fileprovider")
                || component.authorities.stream().anyMatch(a -> a.toLowerCase(Locale.ROOT).contains("fileprovider"));
            if (looksLikeFileProvider && model.apkMetadata != null && model.apkMetadata.providerPathFiles.isEmpty()) {
                findings.add(new AttackSurfaceReport.Finding(
                    "HIGH",
                    "FileProvider may be insufficiently scoped: " + component.name,
                    "The APK exposes a FileProvider-like component but no obvious XML path configuration was found in the package.",
                    "Verify the provider uses a dedicated *_paths.xml file with narrow directories and avoid exposing broad filesystem roots."
                ));
            }
        }
    }

    private static int componentScore(AttackSurfaceModel.Component component) {
        int score = 0;
        if (component.exported) {
            score += switch (component.type) {
                case PROVIDER -> 18;
                case SERVICE -> 14;
                case RECEIVER -> 10;
                case ACTIVITY, ACTIVITY_ALIAS -> 8;
            };
        }
        if (!component.permission.isEmpty() || !component.readPermission.isEmpty() || !component.writePermission.isEmpty()) {
            score -= 5;
        }
        if (!component.intentFilters.isEmpty()) {
            score += 4;
        }
        boolean hasDeepLink = component.intentFilters.stream()
            .flatMap(filter -> filter.dataSpecs.stream())
            .anyMatch(AttackSurfaceModel.DataSpec::isDeepLink);
        if (hasDeepLink) {
            score += 8;
        }
        if (component.grantUriPermissions) {
            score += 10;
        }
        return Math.max(score, 0);
    }

    private static int severityRank(AttackSurfaceReport.Finding finding) {
        return switch (finding.severity()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}
