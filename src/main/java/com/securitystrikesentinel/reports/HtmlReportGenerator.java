package com.securitystrikesentinel.reports;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class HtmlReportGenerator {

    private static final Path REPORTS_DIR = Paths.get("reports");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public void generateSampleHtml(String target, int vulns) throws IOException {
        ensureReportsDirectory();
        File jsonFile = new File("dependency-check-report.json");

        JsonNode root = jsonFile.exists() ? MAPPER.readTree(jsonFile) : null;
        String vulnDetails = (root != null) ? parseJsonVulnerabilities(root) : "<p>No vulnerability data available.</p>";
        String html = buildHtmlReport(target, vulns, vulnDetails, new HashMap<>(), null, null, "N/A", "1.0");

        Files.writeString(REPORTS_DIR.resolve("sample-report.html"), html);
        System.out.println("✔ Report generated: reports/sample-report.html");
    }

    public void generateDetailedReportFromJson(String target, String jsonPath, LocalDateTime scanStart, LocalDateTime scanEnd, String zapVersion, String toolVersion) throws IOException {
        ensureReportsDirectory();
        File jsonFile = new File(jsonPath);
        if (!jsonFile.exists()) throw new FileNotFoundException("JSON file not found: " + jsonPath);

        JsonNode root = MAPPER.readTree(jsonFile);
        int vulnCount = countVulnerabilities(root);
        String vulnDetails = root.has("alerts") ? parseZapAlerts(root) : parseJsonVulnerabilities(root);
        Map<String, Integer> riskStats = calculateRiskStatistics(root);

        String html = buildHtmlReport(target, vulnCount, vulnDetails, riskStats, null, null, "N/A", "1.0");
        Files.writeString(REPORTS_DIR.resolve("detailed-report.html"), html);
        System.out.println("✔ Detailed report generated: reports/detailed-report.html");
    }

    private void ensureReportsDirectory() throws IOException {
        if (!Files.exists(REPORTS_DIR)) Files.createDirectories(REPORTS_DIR);
    }

    private String escapeHtml(String input) {
        return input == null ? "" : input.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;");
    }

    private String parseJsonVulnerabilities(JsonNode root) {
        StringBuilder table = new StringBuilder("<table><tr><th>Source</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>");
        JsonNode dependencies = root.path("dependencies");
        if (!dependencies.isMissingNode()) {
            for (JsonNode dep : dependencies) {
                String fileName = dep.path("fileName").asText(null);
                JsonNode vulns = dep.path("vulnerabilities");
                if (!vulns.isMissingNode() && fileName != null) {
                    for (JsonNode vuln : vulns) {
                        String name = vuln.path("name").asText("Unknown");
                        String severity = vuln.path("severity").asText("N/A");
                        String description = vuln.path("description").asText("No description available.");
                        if (description.length() > 250) description = description.substring(0, 250) + "...";

                        table.append("<tr>")
                             .append("<td>").append(escapeHtml(fileName)).append("</td>")
                             .append("<td>").append(escapeHtml(name)).append("</td>")
                             .append("<td class='").append(severity.toLowerCase()).append("'>").append(severity).append("</td>")
                             .append("<td>").append(escapeHtml(description)).append("</td>")
                             .append("</tr>");
                    }
                }
            }
        } else {
            table.append("<tr><td colspan='4'>No vulnerability data structure recognized in JSON.</td></tr>");
        }
        table.append("</table>");
        return table.toString();
    }

    private String parseZapAlerts(JsonNode root) {
        StringBuilder table = new StringBuilder("<table><tr><th>Alert</th><th>Risk</th><th>URL</th><th>Description</th></tr>");
        JsonNode alerts = root.path("alerts");
        if (alerts.isArray()) {
            for (JsonNode alert : alerts) {
                String name = alert.path("alert").asText("Unknown");
                String risk = alert.path("risk").asText("Informational");
                String url = alert.path("url").asText("N/A");
                String desc = alert.path("description").asText("No description.");
                if (desc.length() > 250) desc = desc.substring(0, 250) + "...";

                table.append("<tr>")
                     .append("<td>").append(escapeHtml(name)).append("</td>")
                     .append("<td class='").append(risk.toLowerCase()).append("'>").append(risk).append("</td>")
                     .append("<td>").append(escapeHtml(url)).append("</td>")
                     .append("<td>").append(escapeHtml(desc)).append("</td>")
                     .append("</tr>");
            }
        }
        table.append("</table>");
        return table.toString();
    }

    private int countVulnerabilities(JsonNode root) {
        if (root.has("alerts")) return root.path("alerts").size();
        if (root.has("dependencies")) {
            int count = 0;
            for (JsonNode dep : root.path("dependencies")) {
                count += dep.path("vulnerabilities").size();
            }
            return count;
        }
        return 0;
    }

    private Map<String, Integer> calculateRiskStatistics(JsonNode root) {
        Map<String, Integer> stats = new HashMap<>(Map.of("High", 0, "Medium", 0, "Low", 0, "Informational", 0));
        if (root.has("alerts")) {
            for (JsonNode alert : root.get("alerts")) {
                String risk = alert.path("risk").asText("Informational");
                stats.merge(risk, 1, Integer::sum);
            }
        }
        return stats;
    }

    private int toInt(Object value) {
        if (value instanceof Integer) return (int) value;
        try { return Integer.parseInt(value.toString()); } catch (Exception e) { return 0; }
    }

    private String buildHtmlReport(String target, int vulnCount, String vulnDetails, Map<String, Integer> stats, LocalDateTime scanStart, LocalDateTime scanEnd, String zapVersion, String toolVersion) {
        String duration = scanStart != null && scanEnd != null ? Duration.between(scanStart, scanEnd).toMinutesPart() + "m " + Duration.between(scanStart, scanEnd).toSecondsPart() + "s" : "N/A";
        String color = vulnCount > 0 ? "#d62828" : "#28a745";
        String statusMsg = vulnCount > 0
            ? "<p><strong>⚠️ Attention:</strong> " + vulnCount + " vulnerability(s) found. Review and mitigate promptly.</p>"
            : "<p><strong>✅ No vulnerabilities found. Target appears secure.</strong></p>";

        int high = toInt(stats.get("High"));
        int medium = toInt(stats.get("Medium"));
        int low = toInt(stats.get("Low"));
        int info = toInt(stats.get("Informational"));

        String versionFooter = String.format("<footer style='margin-top:2em; font-size:0.9em;'>ZAP Version: %s | Tool Version: %s</footer>", escapeHtml(zapVersion != null ? zapVersion : "N/A"), escapeHtml(toolVersion != null ? toolVersion : "N/A"));

        return String.format(
            // original HTML content here (omitted for brevity)
            "... your existing HTML with %s placeholders for duration, versionFooter, etc ...",
            escapeHtml(target), color, vulnCount,
            LocalDateTime.now().format(FORMATTER), duration,
            statusMsg, vulnDetails,
            high, medium, low, info,
            versionFooter
        );
    }
}
