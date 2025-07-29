package com.securitystrikesentinel.scanners.zap;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securitystrikesentinel.auth.ZapAuthManager;
import com.securitystrikesentinel.reports.HtmlReportGenerator;

/**
 * ZapScanner handles integration with the OWASP ZAP API, including scanning, authentication, and report generation.
 */
public class ZapScanner {

    private static final String ZAP_HOST = "localhost";
    private static final int ZAP_PORT = 8080;
    private static final String BASE_URL = String.format("http://%s:%d", ZAP_HOST, ZAP_PORT);
    private static final String OUTPUT_DIR = "reports";
    private static final String JSON_REPORT_PATH = OUTPUT_DIR + "/zap_result.json";
    private static final String PREVIOUS_REPORT_PATH = OUTPUT_DIR + "/zap_result_previous.json";

    private static final boolean USE_API_KEY = true;
    private static final String API_KEY = "1utjr8dcvt4521ujk7d62md5l9";

    private String scanPolicyName = "Default Policy";
    private String contextName;
    private boolean generateHtml;
    private boolean failOnVuln;
    private boolean enableDelta;
    private ZapAuthManager authManager;

    /**
     * Constructor with full configuration.
     */
    public ZapScanner(String contextName, String policyName, boolean generateHtml, boolean failOnVuln, boolean enableDelta, ZapAuthManager authManager) {
        this.contextName = contextName;
        this.scanPolicyName = policyName != null ? policyName : "Default Policy";
        this.generateHtml = generateHtml;
        this.failOnVuln = failOnVuln;
        this.enableDelta = enableDelta;
        this.authManager = authManager;
    }

    /**
     * Basic constructor using only policy.
     */
    public ZapScanner(String scanPolicyName) {
        this.scanPolicyName = scanPolicyName;
    }
    
    private String fetchZapVersion() {
        try {
            String json = sendSimpleGetRequest(BASE_URL + "/JSON/core/view/version/" + getApiParamPrefix());
            return new ObjectMapper().readTree(json).path("version").asText("Unknown");
        } catch (IOException e) {
            return "Unknown";
        }
    }


    /**
     * Executes a full or quick ZAP scan and returns the number of alerts.
     */
    public int scan(String targetUrl, boolean quickScan) throws IOException, InterruptedException {
        verifyZapApiAvailable();

        if (authManager != null) {
            System.out.println("[i] Applying authentication configuration...");
            authManager.configureAuthentication(contextName, targetUrl);
        }

        long siteRtt = measureSiteResponseTime(targetUrl);
        int spiderTimeout = calculateDynamicTimeout(siteRtt, 150);
        int ascanTimeout = calculateDynamicTimeout(siteRtt, 900);

        runZapScan(targetUrl, quickScan, spiderTimeout, ascanTimeout);

        JsonNode alerts = fetchZapAlerts();

        File currentReport = new File(JSON_REPORT_PATH);
        if (currentReport.exists()) {
            Files.copy(currentReport.toPath(), Paths.get(PREVIOUS_REPORT_PATH), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }

        saveJsonReport(alerts);

        if (generateHtml) {
            try {
                HtmlReportGenerator reportGen = new HtmlReportGenerator();
                LocalDateTime scanStart = LocalDateTime.now();

                // ZAP scan logic here...

                // Save JSON before generating report
                saveJsonReport(alerts);
                System.out.println("[✓] JSON report saved. Alert count: " + alerts.path("alerts").size());


                LocalDateTime scanEnd = LocalDateTime.now();
                String zapVersion = fetchZapVersion();
                String toolVersion = "1.0"; // Update if version info is available elsewhere

                reportGen.generateDetailedReportFromJson(
                    targetUrl,
                    JSON_REPORT_PATH,
                    scanStart,
                    scanEnd,
                    zapVersion,
                    toolVersion
                );
                System.out.println("[✓] HTML Report generated at: reports/detailed-report.html");

                if (enableDelta) {
                    generateDeltaComparison();
                }

            } catch (Exception e) {
                System.err.println("[!] Failed to generate HTML report: " + e.getMessage());
            }
        }

        int highSeverity = 0;
        for (JsonNode alert : alerts.path("alerts")) {
            String risk = alert.path("risk").asText("").toLowerCase();
            if ("high".equals(risk)) {
                highSeverity++;
            }
        }

        if (failOnVuln && highSeverity > 0) {
            System.err.printf("[!] CI Mode: %d high severity issues found. Failing the build.%n", highSeverity);
            System.exit(1);
        }
        System.out.println("Report file exists? " + Files.exists(Paths.get("reports/zap_result.json")));
        System.out.println("Report file size: " + Files.size(Paths.get("reports/zap_result.json")) + " bytes");

        return alerts.path("alerts").size();
    }

    /**
     * Executes spider and active scan phases.
     */
    public void runZapScan(String targetUrl, boolean quickScan, int spiderTimeout, int ascanTimeout)
            throws IOException, InterruptedException {

        System.out.println("[*] Starting ZAP scan for: " + targetUrl);
        System.out.println("[→] Using timeouts — Spider: " + spiderTimeout + "s | AScan: " + ascanTimeout + "s");

        String spiderScanId = retryScanStart("spider", targetUrl);
        pollStatus(BASE_URL + "/JSON/spider/view/status/?scanId=" + spiderScanId + getApiParam(), "Spider", spiderTimeout);

        if (!quickScan) {
            String ascanId = retryScanStart("ascan", targetUrl);
            pollStatus(BASE_URL + "/JSON/ascan/view/status/?scanId=" + ascanId + getApiParam(), "Active", ascanTimeout);
        }
    }

    private String retryScanStart(String type, String targetUrl) throws IOException {
        int retries = 3;
        while (retries-- > 0) {
            try {
                return startScanAndGetId(type, targetUrl);
            } catch (IOException e) {
                System.err.printf("[!] %s scan failed to start. Retrying... (%d attempts left)%n", type, retries);
                try { Thread.sleep(3000); } catch (InterruptedException ignored) {}
            }
        }
        throw new IOException("Failed to start " + type + " scan after retries.");
    }

    private long measureSiteResponseTime(String targetUrl) {
        try {
            URL url = new URL(targetUrl);
            long start = System.currentTimeMillis();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.connect();
            conn.getResponseCode();
            long end = System.currentTimeMillis();
            long rtt = Math.min(end - start, 5000);
            System.out.println("[i] Site RTT: " + rtt + "ms");
            return rtt;
        } catch (Exception e) {
            System.err.println("[!] Failed to measure RTT. Default used.");
            return 2000;
        }
    }

    private int calculateDynamicTimeout(long rttMs, int baseSeconds) {
        double multiplier = 1.0 + (rttMs / 1000.0) * 0.3;
        return Math.max((int) Math.ceil(baseSeconds * multiplier), baseSeconds);
    }

    private String startScanAndGetId(String type, String targetUrl) throws IOException {
        String endpoint = switch (type) {
            case "spider" -> "/JSON/spider/action/scan/";
            case "ascan" -> "/JSON/ascan/action/scan/";
            default -> throw new IllegalArgumentException("Unsupported scan type: " + type);
        };

        String encodedUrl = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        String requestUrl = String.format("%s%s?url=%s%s", BASE_URL, endpoint, encodedUrl, getApiParam());

        if ("ascan".equals(type)) {
            requestUrl += "&scanPolicyName=" + URLEncoder.encode(scanPolicyName, StandardCharsets.UTF_8);
        }

        System.out.println("[>] Starting " + type + " scan...");
        String response = sendSimpleGetRequest(requestUrl);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonResponse = mapper.readTree(response);
        return jsonResponse.path("scan").asText("0");
    }

    private void pollStatus(String statusUrl, String phaseName, int timeoutSeconds) throws IOException, InterruptedException {
        int elapsed = 0;
        int interval = 5;
        ObjectMapper mapper = new ObjectMapper();

        while (elapsed < timeoutSeconds) {
            String response = sendSimpleGetRequest(statusUrl);
            JsonNode jsonResponse = mapper.readTree(response);
            String progress = jsonResponse.path("status").asText("0");

            System.out.printf("[%s] Progress: %s%%%n", phaseName, progress);
            if ("100".equals(progress)) {
                System.out.printf("[✓] %s scan finished.%n", phaseName);
                return;
            }

            TimeUnit.SECONDS.sleep(interval);
            elapsed += interval;
        }

        throw new IOException(phaseName + " scan did not complete within expected time (" + timeoutSeconds + "s).");
    }

    private JsonNode fetchZapAlerts() throws IOException {
        String url = BASE_URL + "/JSON/core/view/alerts/" + getApiParamPrefix();
        String json = sendSimpleGetRequest(url);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(json);
        ArrayNode alerts = (ArrayNode) root.path("alerts");

        ObjectNode result = mapper.createObjectNode();
        result.set("alerts", alerts != null ? alerts : mapper.createArrayNode());
        return result;
    }

    private void saveJsonReport(JsonNode report) throws IOException {
        Files.createDirectories(Paths.get(OUTPUT_DIR));
        ObjectMapper mapper = new ObjectMapper();
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(JSON_REPORT_PATH), StandardCharsets.UTF_8)) {
            writer.write(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
        }
        System.out.println("[✓] ZAP scan report saved to: " + JSON_REPORT_PATH);
    }

    private void generateDeltaComparison() {
        try {
            File previousFile = new File(PREVIOUS_REPORT_PATH);
            File currentFile = new File(JSON_REPORT_PATH);

            if (!previousFile.exists()) return;

            ObjectMapper mapper = new ObjectMapper();
            JsonNode prev = mapper.readTree(previousFile);
            JsonNode curr = mapper.readTree(currentFile);

            int prevCount = prev.path("alerts").size();
            int currCount = curr.path("alerts").size();
            int delta = currCount - prevCount;

            System.out.printf("[Δ] Delta Analysis: Previous=%d, Current=%d, Δ=%+d%n", prevCount, currCount, delta);
        } catch (IOException e) {
            System.err.println("[!] Failed to generate delta report: " + e.getMessage());
        }
    }

    /**
     * Verifies the ZAP API is accessible.
     */
    public static void verifyZapApiAvailable() throws IOException {
        URL url = new URL(BASE_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        conn.connect();

        int responseCode = conn.getResponseCode();
        if (responseCode != 200 && responseCode != 403) {
            throw new IOException("ZAP not reachable. HTTP status: " + responseCode);
        }

        System.out.println("[✓] ZAP API is up " + (USE_API_KEY ? "(API key enabled)" : "(no API key)"));
    }

    /**
     * Sends a simple GET request to the specified URL.
     */
    public static String sendSimpleGetRequest(String urlStr) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");

        int code = conn.getResponseCode();
        InputStream is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) result.append(line);
            return result.toString();
        }
    }

    private static String getApiParam() {
        return USE_API_KEY ? "&apikey=" + API_KEY : "";
    }

    private static String getApiParamPrefix() {
        return USE_API_KEY ? "?apikey=" + API_KEY : "";
    }
}
