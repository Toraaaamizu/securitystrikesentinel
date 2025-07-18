package com.securitystrikesentinel.reports;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Generates HTML reports from JSON-based vulnerability scan data.
 */
public class HtmlReportGenerator {

    private static final Path REPORTS_DIR = Paths.get("reports");
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void generateSampleHtml(String target, int vulns) throws IOException {
        ensureReportsDirectory();

        File jsonFile = new File("dependency-check-report.json");
        String vulnDetails = jsonFile.exists() ? parseJsonVulnerabilities(jsonFile) : "<p>No vulnerability data available.</p>";
        String html = buildHtmlReport(target, vulns, vulnDetails, new HashMap<>());

        try (FileWriter writer = new FileWriter(REPORTS_DIR.resolve("sample-report.html").toFile())) {
            writer.write(html);
            System.out.println("✔ Report generated: reports/sample-report.html");
        }
    }

    public void generateDetailedReportFromJson(String target, String jsonPath) throws IOException {
        ensureReportsDirectory();

        File jsonFile = new File(jsonPath);
        if (!jsonFile.exists()) throw new FileNotFoundException("JSON file not found: " + jsonPath);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(jsonFile);

        int vulnCount = countVulnerabilities(jsonFile);
        String vulnDetails = root.has("alerts") ? parseZapAlerts(root) : parseJsonVulnerabilities(jsonFile);
        Map<String, Integer> riskStats = calculateRiskStatistics(root);

        String html = buildHtmlReport(target, vulnCount, vulnDetails, riskStats);

        try (FileWriter writer = new FileWriter(REPORTS_DIR.resolve("detailed-report.html").toFile())) {
            writer.write(html);
            System.out.println("✔ Detailed report generated: reports/detailed-report.html");
        }
    }

    private void ensureReportsDirectory() throws IOException {
        if (!Files.exists(REPORTS_DIR)) {
            Files.createDirectories(REPORTS_DIR);
        }
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }

    private String parseJsonVulnerabilities(File jsonFile) {
        StringBuilder table = new StringBuilder();
        ObjectMapper mapper = new ObjectMapper();

        try {
            JsonNode root = mapper.readTree(jsonFile);
            table.append("<table>");
            table.append("<tr><th>Source</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr>");

            if (root.has("dependencies")) {
                JsonNode dependencies = root.path("dependencies");
                for (JsonNode dep : dependencies) {
                    String fileName = dep.path("fileName").asText(null);
                    JsonNode vulns = dep.path("vulnerabilities");

                    if (!vulns.isMissingNode() && fileName != null) {
                        for (JsonNode vuln : vulns) {
                            String name = vuln.path("name").asText("Unknown");
                            String severity = vuln.path("severity").asText("N/A");
                            String description = vuln.path("description").asText("No description available.");
                            if (description.length() > 250) {
                                description = description.substring(0, 250) + "...";
                            }

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
        } catch (IOException e) {
            table.append("<p>Error reading vulnerability data: ").append(e.getMessage()).append("</p>");
        }

        return table.toString();
    }

    private String parseZapAlerts(JsonNode root) {
        StringBuilder table = new StringBuilder();
        table.append("<table>");
        table.append("<tr><th>Alert</th><th>Risk</th><th>URL</th><th>Description</th></tr>");

        JsonNode alerts = root.get("alerts");
        if (alerts != null && alerts.isArray()) {
            for (JsonNode alert : alerts) {
                String name = alert.path("alert").asText("Unknown");
                String risk = alert.path("risk").asText("N/A");
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

    private int countVulnerabilities(File jsonFile) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(jsonFile);

            if (root.has("alerts")) {
                return root.path("alerts").size();
            } else if (root.has("dependencies")) {
                int count = 0;
                for (JsonNode dep : root.path("dependencies")) {
                    JsonNode vulns = dep.path("vulnerabilities");
                    if (vulns != null) {
                        count += vulns.size();
                    }
                }
                return count;
            }
        } catch (IOException e) {
            System.err.println("Error counting vulnerabilities: " + e.getMessage());
        }
        return 0;
    }

    private Map<String, Integer> calculateRiskStatistics(JsonNode root) {
        Map<String, Integer> stats = new HashMap<>();
        stats.put("High", 0);
        stats.put("Medium", 0);
        stats.put("Low", 0);
        stats.put("Informational", 0);

        if (root.has("alerts")) {
            for (JsonNode alert : root.get("alerts")) {
                String risk = alert.path("risk").asText("Informational");
                stats.merge(risk, 1, Integer::sum);
            }
        }

        return stats;
    }

    private String generateChartScript(Map<String, Integer> stats) {
        return String.format("""
            <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
            <div style=\"max-width: 600px; margin:auto\">
            <canvas id=\"vulnChart\" width=\"400\" height=\"300\"></canvas>
            </div>
            <script>
            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {
              type: 'doughnut',
              data: {
                labels: ['High', 'Medium', 'Low', 'Informational'],
                datasets: [{
                  label: 'Vulnerabilities',
                  data: [%d, %d, %d, %d],
                  backgroundColor: ['#d62828', '#e67700', '#f4a261', '#a1a1a1'],
                  borderColor: ['#600000', '#994d00', '#996633', '#666666'],
                  borderWidth: 2
                }]
              },
              options: {
                responsive: true,
                plugins: {
                 tooltip: {
        		  callbacks: {
        		    label: function(context) {
        		      let total = context.dataset.data.reduce((a, b) => a + b, 0);
        		      let value = context.raw;
        		      let percent = ((value / total) * 100).toFixed(1);
        		      return context.label + ': ' + value + ' (' + percent + '%%)';
        		    }
        		  }
        		}
                }
              }
            });
            </script>
        """,
        stats.getOrDefault("High", 0),
        stats.getOrDefault("Medium", 0),
        stats.getOrDefault("Low", 0),
        stats.getOrDefault("Informational", 0)) +
        generateRiskSummaryTable(stats);
    }

    private String generateRiskSummaryTable(Map<String, Integer> stats) {
        return String.format("""
            <h3>Risk-Level Summary</h3>
            <table>
              <tr><th>Risk Level</th><th>Count</th></tr>
              <tr><td class='high'>High</td><td>%d</td></tr>
              <tr><td class='medium'>Medium</td><td>%d</td></tr>
              <tr><td class='low'>Low</td><td>%d</td></tr>
              <tr><td>Informational</td><td>%d</td></tr>
            </table>
        """,
        stats.getOrDefault("High", 0),
        stats.getOrDefault("Medium", 0),
        stats.getOrDefault("Low", 0),
        stats.getOrDefault("Informational", 0));
    }

    private String buildHtmlReport(String target, int vulnCount, String vulnDetails, Map<String, Integer> stats) {
        String color = vulnCount > 0 ? "#d62828" : "#28a745";
        String statusMsg = vulnCount > 0
            ? "<p><strong>⚠️ Attention:</strong> " + vulnCount + " vulnerability(s) found. Review and mitigate promptly.</p>"
            : "<p><strong>✅ No vulnerabilities found. Target appears secure.</strong></p>";
        String chartScript = generateChartScript(stats);

        return String.format("""
            <!DOCTYPE html>
            <html lang='en'>
            <head>
              <meta charset='UTF-8'>
              <title>Security Scan Report</title>
              <style>
                body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 2em; }
                .container { background: #fff; padding: 2em; border-radius: 8px; max-width: 1000px; margin: auto; box-shadow: 0 4px 10px rgba(0,0,0,0.1); overflow-x: auto; }
                h1 { color: #d62828; }
                h2, h3 { margin-top: 2em; color: #333; }
                .info, .summary, .vulnerabilities { margin-bottom: 2em; }
                .vuln-count { font-weight: bold; color: %s; }
                .timestamp { color: #888; font-size: 0.9em; }
                table { width: 100%%; border-collapse: collapse; margin-top: 1em; table-layout: fixed; word-wrap: break-word; }
                th, td { padding: 10px; border: 1px solid #ccc; word-break: break-word; }
                th { background-color: #f9f9f9; }
                .high { color: #d62828; font-weight: bold; }
                .medium { color: #e67700; font-weight: bold; }
                .low { color: #f4a261; }
              </style>
            </head>
            <body>
              <div class="container">
                <h1>Security Scan Report</h1>
                <div class="info">
                  <p><strong>Target:</strong> %s</p>
                  <p><strong>Vulnerabilities Found:</strong> <span class="vuln-count">%d</span></p>
                  <p class="timestamp">Generated: %s</p>
                </div>
                <div class="summary">
                  <h2>Summary</h2>
                  <p>This report outlines the results of the automated security scan.</p>
                  %s
                  %s
                </div>
                <div class="vulnerabilities">
                  <h2>Detailed Vulnerabilities</h2>
                  %s
                </div>
              </div>
            </body>
            </html>
        """,
        color,
        escapeHtml(target),
        vulnCount,
        LocalDateTime.now().format(FORMATTER),
        statusMsg,
        chartScript,
        vulnDetails);
    }
}
