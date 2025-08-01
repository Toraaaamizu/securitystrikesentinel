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

        try {
            JsonNode root = MAPPER.readTree(jsonFile);
            int vulnCount = countVulnerabilities(root);
            String vulnDetails = root.has("alerts") ? parseZapAlerts(root) : parseJsonVulnerabilities(root);
            Map<String, Integer> riskStats = calculateRiskStatistics(root);

            String html = buildHtmlReport(target, vulnCount, vulnDetails, riskStats, scanStart, scanEnd, zapVersion, toolVersion);
            Path reportPath = REPORTS_DIR.resolve("detailed-report.html");
            Files.writeString(reportPath, html);
            System.out.println("✔ Detailed report generated: " + reportPath);
        } catch (IOException e) {
            throw new IOException("[!] Failed to read or parse JSON: " + e.getMessage(), e);
        }
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
        String duration = (scanStart != null && scanEnd != null)
                ? Duration.between(scanStart, scanEnd).toMinutesPart() + "m " + Duration.between(scanStart, scanEnd).toSecondsPart() + "s"
                : "N/A";

        String color = vulnCount > 0 ? "#d62828" : "#28a745";
        String statusMsg = vulnCount > 0
                ? "<p><strong>⚠️ Attention:</strong> " + vulnCount + " vulnerability(s) found. Review and mitigate promptly.</p>"
                : "<p><strong>✅ No vulnerabilities found. Target appears secure.</strong></p>";

        int high = toInt(stats.get("High"));
        int medium = toInt(stats.get("Medium"));
        int low = toInt(stats.get("Low"));
        int info = toInt(stats.get("Informational"));

        String versionFooter = String.format(
                "<footer style='margin-top:2em; font-size:0.9em;'>ZAP Version: %s | Tool Version: %s</footer>",
                escapeHtml(zapVersion != null ? zapVersion : "N/A"),
                escapeHtml(toolVersion != null ? toolVersion : "1.0")
        );

        return """
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>Security Strike Sentinel Report</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; background: #f8f9fa; }
                h1 { color: %s; }
                table { border-collapse: collapse; width: 100%%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; }
                th { background-color: #343a40; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .high { color: #d62828; font-weight: bold; }
                .medium { color: #f77f00; font-weight: bold; }
                .low { color: #fcbf49; font-weight: bold; }
                .informational { color: #6c757d; }
            </style>
            <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
        </head>
        <body>
            <h1>Security Strike Sentinel</h1>
            <p><strong>Target:</strong> %s</p>
            <p><strong>Scan Date:</strong> %s</p>
            <p><strong>Scan Duration:</strong> %s</p>
            %s

            <h2>Risk Breakdown</h2>
            <ul>
                <li><strong>High:</strong> %d</li>
                <li><strong>Medium:</strong> %d</li>
                <li><strong>Low:</strong> %d</li>
                <li><strong>Informational:</strong> %d</li>
            </ul>

            <h2>Risk Chart</h2>
            <canvas id="riskChart" width="500" height="250"></canvas>
            <script>
                const ctx = document.getElementById('riskChart').getContext('2d');
                const chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['High Risk', 'Medium Risk', 'Low Risk', 'Informational'],
                        datasets: [{
                            label: 'Severity Count',
                            data: [%d, %d, %d, %d],
                            backgroundColor: ['#d62828', '#f77f00', '#fcbf49', '#adb5bd'],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        plugins: {
                            legend: {
                                display: true,
                                labels: {
                                    color: '#000',
                                    font: {
                                        size: 14
                                    }
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: 'Number of Issues'
                                }
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Risk Categories'
                                }
                            }
                        }
                    }
                });
            </script>

            <h2>Vulnerability Details</h2>
            %s

            %s
        </body>
        </html>
        """.formatted(
                color,
                escapeHtml(target),
                LocalDateTime.now().format(FORMATTER),
                duration,
                statusMsg,
                high, medium, low, info,
                high, medium, low, info,
                vulnDetails,
                versionFooter
        );
    }
}
