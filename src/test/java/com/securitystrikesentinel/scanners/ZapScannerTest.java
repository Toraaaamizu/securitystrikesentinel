package com.securitystrikesentinel.scanners;

import com.securitystrikesentinel.scanners.zap.ZapScanner;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class ZapScannerTest {

    private static final String TEST_TARGET = "http://zero.webappsecurity.com"; // Public demo site with login
    private static final Path REPORT_PATH = Paths.get("reports/detailed-report.html");

    @BeforeEach
    public void cleanupReports() throws Exception {
        Files.deleteIfExists(REPORT_PATH);
    }

    @Test
    @Disabled("⚠️ Optional: This test runs a live ZAP scan. Requires ZAP listening on localhost:8080.")
    public void testQuickUnauthenticatedScan() throws Exception {
        ZapScanner scanner = new ZapScanner(
            null,                // context
            "Default Policy",    // scan policy
            true,                // generate HTML report
            false,               // failOnVuln
            false,               // enable delta
            null,                // authManager
            false                // generateCsv (new parameter)
        );

        int findings = scanner.scan(TEST_TARGET, true, -1, -1); // quick scan

        assertTrue(Files.exists(REPORT_PATH), "Expected detailed-report.html to be created.");

        String content = Files.readString(REPORT_PATH, StandardCharsets.UTF_8);
        assertTrue(
            content.contains("<h1>Security Strike Sentinel</h1>"),
            "Expected report header not found. Actual content:\n" +
            content.substring(0, Math.min(content.length(), 500)) + "..."
        );

        System.out.printf("✓ Quick scan finished. Findings: %d%n", findings);
    }

    @AfterEach
    public void teardown() throws Exception {
        Files.deleteIfExists(REPORT_PATH);
    }
}
