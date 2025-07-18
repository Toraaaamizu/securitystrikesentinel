package com.securitystrikesentinel.reports;

import org.junit.jupiter.api.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class HtmlReportGeneratorTest {

    private static final String TEST_URL = "http://testsite.com";
    private static final int TEST_FINDINGS = 3;
    private static final Path SAMPLE_REPORT_PATH = Path.of("reports/sample-report.html");
    private static final Path DETAILED_REPORT_PATH = Path.of("reports/detailed-report.html");
    private static final Path JSON_REPORT_PATH = Path.of("reports/dependency-check-report.json");

    @BeforeEach
    public void setupMockJsonReport() throws IOException {
        Files.createDirectories(JSON_REPORT_PATH.getParent());
        if (!Files.exists(JSON_REPORT_PATH)) {
            String mockJson = """
                {
                  "dependencies": [
                    {
                      "fileName": "example-lib.jar",
                      "vulnerabilities": [
                        {
                          "name": "CVE-2023-0001",
                          "severity": "High",
                          "description": "Example vulnerability description"
                        }
                      ]
                    }
                  ]
                }
                """;
            Files.writeString(JSON_REPORT_PATH, mockJson);
            System.out.println("📝 [Setup] Created mock JSON report: " + JSON_REPORT_PATH);
        }
    }

    @Test
    public void testGenerateSampleHtml() throws Exception {
        HtmlReportGenerator generator = new HtmlReportGenerator();
        generator.generateSampleHtml(TEST_URL, TEST_FINDINGS);

        assertTrue(Files.exists(SAMPLE_REPORT_PATH), "Expected sample-report.html to be created.");
        assertTrue(Files.size(SAMPLE_REPORT_PATH) > 0, "Generated HTML report should not be empty.");
    }

    @Test
    public void testGenerateDetailedReportFromJson() throws Exception {
        HtmlReportGenerator generator = new HtmlReportGenerator();
        generator.generateDetailedReportFromJson(TEST_URL, JSON_REPORT_PATH.toString());

        assertTrue(Files.exists(DETAILED_REPORT_PATH), "Expected detailed-report.html to be created.");
        assertTrue(Files.size(DETAILED_REPORT_PATH) > 0, "Generated detailed HTML report should not be empty.");
    }

    @AfterEach
    public void cleanupReports() throws Exception {
        deleteIfExists(SAMPLE_REPORT_PATH);
        deleteIfExists(DETAILED_REPORT_PATH);
        deleteIfExists(JSON_REPORT_PATH);
    }

    private void deleteIfExists(Path path) throws IOException {
        if (Files.exists(path)) {
            Files.delete(path);
            System.out.println("🧹 [Cleanup] Deleted report: " + path);
        }
    }
}
