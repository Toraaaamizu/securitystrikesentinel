package com.securitystrikesentinel.reports;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
        String html = buildHtmlReport(target, vulns, vulnDetails, new HashMap<>());

        Files.writeString(REPORTS_DIR.resolve("sample-report.html"), html);
        System.out.println("✔ Report generated: reports/sample-report.html");
    }

    public void generateDetailedReportFromJson(String target, String jsonPath) throws IOException {
        ensureReportsDirectory();
        File jsonFile = new File(jsonPath);
        if (!jsonFile.exists()) throw new FileNotFoundException("JSON file not found: " + jsonPath);

        JsonNode root = MAPPER.readTree(jsonFile);
        int vulnCount = countVulnerabilities(root);
        String vulnDetails = root.has("alerts") ? parseZapAlerts(root) : parseJsonVulnerabilities(root);
        Map<String, Integer> riskStats = calculateRiskStatistics(root);

        String html = buildHtmlReport(target, vulnCount, vulnDetails, riskStats);
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

    private String buildHtmlReport(String target, int vulnCount, String vulnDetails, Map<String, Integer> stats) {
        String color = vulnCount > 0 ? "#d62828" : "#28a745";
        String statusMsg = vulnCount > 0
            ? "<p><strong>⚠️ Attention:</strong> " + vulnCount + " vulnerability(s) found. Review and mitigate promptly.</p>"
            : "<p><strong>✅ No vulnerabilities found. Target appears secure.</strong></p>";

        int high = toInt(stats.get("High"));
        int medium = toInt(stats.get("Medium"));
        int low = toInt(stats.get("Low"));
        int info = toInt(stats.get("Informational"));

        return String.format("""
            <!DOCTYPE html>
            <html lang='en'>
            <head>
              <meta charset='UTF-8'>
              <title>Security Scan Report</title>
              <style>
                body { font-family: sans-serif; background: #fff; color: #111; transition: background 0.3s, color 0.3s; }
                body.dark { background: #121212; color: #eee; }
                .container { max-width: 960px; margin: auto; padding: 2em; }
                table { width: 100%%; border-collapse: collapse; margin: 1em 0; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                th { background: #f4f4f4; }
                body.dark th { background: #333; }
                .high { color: #d62828; } .medium { color: #e67700; } .low { color: #f4a261; }
                .theme-toggle { float: right; margin-bottom: 1em; }
              </style>
              <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
              <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-pattern@3.3.1/dist/chartjs-plugin-pattern.min.js"></script>
            </head>
            <body>
              <div class="container">
                <button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Light/Dark Mode</button>
                <h1>Security Scan Report</h1>
                <div class="info">
                  <p><strong>Target:</strong> %s</p>
                  <p><strong>Vulnerabilities Found:</strong> <span style="color:%s;">%d</span></p>
                  <p class="timestamp">Generated: %s</p>
                </div>
                <div class="summary">
                  <h2>Summary</h2>
                  %s
                  <div style="max-width: 600px; margin:auto">
                    <button onclick="toggleChart()" style="margin-bottom:10px;">Toggle Chart Visibility</button>
                    <div id="chartContainer">
                      <canvas id="vulnChart" width="400" height="300"></canvas>
                    </div>
                  </div>
                </div>
                <div class="vulnerabilities">
                  <h2>Detailed Vulnerabilities</h2>
                  %s
                </div>
              </div>
              <script>
                function toggleTheme() {
                  const body = document.body;
                  const theme = body.classList.contains('dark') ? '' : 'dark';
                  body.className = theme;
                  localStorage.setItem('reportTheme', theme);
                }

                function initTheme() {
                  if (localStorage.getItem('reportTheme') === 'dark') {
                    document.body.className = 'dark';
                  }
                }

                function toggleChart() {
                  const c = document.getElementById('chartContainer');
                  c.style.display = (c.style.display === 'none') ? 'block' : 'none';
                }

                window.onload = function () {
                  initTheme();

                  const high = %d, medium = %d, low = %d, info = %d;
                  const data = [high, medium, low, info];
                  const total = data.reduce((a, b) => a + b, 0);

                  if (total === 0) {
                    document.getElementById('chartContainer').innerHTML =
                      "<p style='text-align:center;'>No vulnerabilities to visualize.</p>";
                    return;
                  }

                  const ctx = document.getElementById('vulnChart').getContext('2d');
                  const plugin = window['chartjs-plugin-pattern'];
                  const usePattern = plugin && plugin.Pattern && plugin.Pattern.draw;

                  const backgroundColor = usePattern ? [
                    plugin.Pattern.draw('diagonal', '#d62828'),
                    plugin.Pattern.draw('zigzag', '#e67700'),
                    plugin.Pattern.draw('dot', '#f4a261'),
                    plugin.Pattern.draw('line', '#a1a1a1')
                  ] : ['#d62828', '#e67700', '#f4a261', '#a1a1a1'];

                  if (usePattern && Chart.registry && plugin.default) {
                    Chart.register(plugin.default);
                  }

                  new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                      labels: ['High', 'Medium', 'Low', 'Informational'],
                      datasets: [{
                        label: 'Vulnerabilities',
                        data: data,
                        backgroundColor: backgroundColor,
                        borderColor: ['#600000', '#994d00', '#996633', '#666666'],
                        borderWidth: 2
                      }]
                    },
                    options: {
                      responsive: true,
                      plugins: {
                        tooltip: {
                          callbacks: {
                            label: function (ctx) {
                              const val = ctx.raw;
                              const percent = ((val / total) * 100).toFixed(1);
                              return ctx.label + ': ' + val + ' (' + percent + '%%)';
                            }
                          }
                        }
                      }
                    }
                  });
                };
              </script>
            </body>
            </html>
            """,
            escapeHtml(target), color, vulnCount,
            LocalDateTime.now().format(FORMATTER),
            statusMsg, vulnDetails,
            high, medium, low, info
        );
    }

}
