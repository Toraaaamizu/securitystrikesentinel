package com.securitystrikesentinel.scanners;

import com.securitystrikesentinel.scanners.zap.ZapScanner;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

public class ZapScannerTest {

    private static final String TEST_TARGET = "http://testhtml5.vulnweb.com"; // Public demo with login
    private static final Path REPORT_PATH = Paths.get("reports/detailed-report.html");

    @BeforeEach
    public void cleanupReports() throws Exception {
        Files.deleteIfExists(REPORT_PATH);
    }

    @Test
    @Disabled("⚠️ Optional: This test runs a live ZAP scan. Requires ZAP listening on localhost:8080.")
    public void testQuickUnauthenticatedScan() throws Exception {
        ZapScanner scanner = new ZapScanner(
                null,                   // context
                "Default Policy",       // scan policy
                true,                   // generate HTML report
                false,                  // failOnVuln
                false,                  // enable delta
                null                    // authManager
        );

        int findings = scanner.scan(TEST_TARGET, true, -1, -1); // quick scan

        assertTrue(Files.exists(REPORT_PATH), "Expected detailed-report.html to be created.");
        String content = Files.readString(REPORT_PATH, StandardCharsets.UTF_8);
        assertTrue(
            content.contains("Security Scan Report") || content.contains("Vulnerabilities Found"),
            "Expected key header content in report but got:\n" +
            content.substring(0, Math.min(content.length(), 500)) + "..."
        );

        System.out.printf("✓ Quick scan finished. Findings: %d%n", findings);
    }

    @AfterEach
    public void teardown() throws Exception {
        Files.deleteIfExists(REPORT_PATH);
    }
}
