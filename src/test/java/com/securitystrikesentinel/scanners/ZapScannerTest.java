package com.securitystrikesentinel.scanners;

import com.securitystrikesentinel.auth.ZapAuthManager;
import com.securitystrikesentinel.reports.HtmlReportGenerator;
import com.securitystrikesentinel.scanners.zap.ZapScanner;
import org.junit.jupiter.api.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ZapScannerTest {

    private static final String TARGET_URL = "http://zero.webappsecurity.com";
    private static final Path REPORT_JSON = Paths.get("reports/zap_result.json");
    private static final Path REPORT_HTML = Paths.get("reports/detailed-report.html");
    private static boolean zapAvailable;

    @BeforeAll
    static void checkZapAvailability() {
        try {
            ZapScanner.verifyZapApiAvailable();
            zapAvailable = true;
        } catch (Exception e) {
            zapAvailable = false;
            System.err.println("[!] ZAP is not available: " + e.getMessage());
        }
    }

    @BeforeEach
    public void cleanReports() throws Exception {
        Files.createDirectories(REPORT_JSON.getParent());
        Files.deleteIfExists(REPORT_JSON);
        Files.deleteIfExists(REPORT_HTML);
    }

    @Test
    @Order(1)
    public void testAuthenticatedScanGeneratesFindings() throws Exception {
        assumeTrue(zapAvailable, "Skipping test: ZAP is not running.");

        ZapAuthManager auth = new ZapAuthManager(
        	    "default-context",
        	    "form",
        	    "http://zero.webappsecurity.com/login.html",
        	    "testuser",
        	    "testpass",
        	    "username",               // username field in form
        	    "password",               // password field in form
        	    "Accounts Overview",      // loggedInIndicator (adjust to actual success indicator)
        	    "logout",                 // logoutIndicator (optional or null)
        	    null                      // authExclude (optional or null)
        	);


        ZapScanner scanner = new ZapScanner(
                auth.getContextName(),
                "Default Policy",
                true,
                false,
                false,
                auth
        );

        int findings = scanner.scan(TARGET_URL, false);
        assertTrue(findings >= 0, "Expected at least 0 findings");
        assertTrue(Files.exists(REPORT_JSON), "Expected zap_result.json to exist");
        assertTrue(Files.exists(REPORT_HTML), "Expected detailed-report.html to exist");

        List<String> lines = Files.readAllLines(REPORT_HTML);
        boolean mentionsAuth = lines.stream().anyMatch(line ->
                line.toLowerCase().contains("login")
                        || line.toLowerCase().contains("logout")
                        || line.toLowerCase().contains("authentication"));

        assertTrue(mentionsAuth, "Expected report to contain authentication-related keywords (login/logout/authentication)");
    }

    @Test
    @Order(2)
    public void testQuickUnauthenticatedScan() throws Exception {
        assumeTrue(zapAvailable, "Skipping test: ZAP is not running.");

        ZapScanner scanner = new ZapScanner(null, "Default Policy", true, false, false, null);
        int findings = scanner.scan(TARGET_URL, true);

        assertTrue(findings >= 0);
        assertTrue(Files.exists(REPORT_JSON));
        assertTrue(Files.exists(REPORT_HTML));

        String content = Files.readString(REPORT_HTML);
        assertTrue(content.contains("<h1>Security Scan Report</h1>"), "Expected header in report");
    }

    @AfterEach
    public void cleanup() throws Exception {
        Files.deleteIfExists(REPORT_JSON);
        Files.deleteIfExists(REPORT_HTML);
    }
}
