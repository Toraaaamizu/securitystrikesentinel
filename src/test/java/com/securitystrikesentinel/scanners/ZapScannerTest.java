package com.securitystrikesentinel.scanners;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.securitystrikesentinel.scanners.zap.ZapScanner;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class ZapScannerTest {

    private static final String testTargetUrl = "http://zero.webappsecurity.com";

    @BeforeAll
    static void checkZapRunning() {
        try {
            ZapScanner.verifyZapApiAvailable();
        } catch (Exception e) {
            fail("❌ ZAP API is not available: " + e.getMessage());
        }
    }

    @Test
    void testFullScanGeneratesReportAndFindings() {
        assertTimeoutPreemptively(Duration.ofMinutes(40), () -> {
            try {
                ZapScanner scanner = new ZapScanner(
                        null,               // contextName
                        "Default Policy",   // scanPolicyName
                        true,               // generateHtml
                        false,              // failOnVuln
                        true                // enableDelta
                );

                int findings = scanner.scan(testTargetUrl, false); // Full scan

                assertTrue(findings >= 0, "❌ Expected non-negative number of findings.");
                assertTrue(Files.exists(Paths.get("reports/zap_result.json")),
                        "❌ Expected 'zap_result.json' report to exist.");
            } catch (Exception e) {
                e.printStackTrace();
                fail("❌ Exception during full scan: " + e.getMessage());
            }
        });
    }

    @Test
    void testQuickScanGeneratesReportAndFindings() {
        assertTimeoutPreemptively(Duration.ofMinutes(5), () -> {
            try {
                ZapScanner scanner = new ZapScanner(
                        null,
                        "Default Policy",
                        true,
                        false,
                        true
                );

                int findings = scanner.scan(testTargetUrl, true); // Quick scan

                assertTrue(findings >= 0, "❌ Expected non-negative number of findings.");
                assertTrue(Files.exists(Paths.get("reports/zap_result.json")),
                        "❌ Expected 'zap_result.json' report to exist.");
            } catch (Exception e) {
                e.printStackTrace();
                fail("❌ Exception during quick scan: " + e.getMessage());
            }
        });
    }
}
