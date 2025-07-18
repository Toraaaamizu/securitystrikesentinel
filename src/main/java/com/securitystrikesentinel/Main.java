package com.securitystrikesentinel;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.securitystrikesentinel.reports.HtmlReportGenerator;
import com.securitystrikesentinel.scanners.ZapScanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

    public static class CLIOptions {

        @Parameter(names = {"--zapscan", "-z"}, description = "Run ZAP scan on target")
        private String zapTarget;

        @Parameter(names = {"--quick"}, description = "Use quick mode (passive scan only, no active attack)")
        private boolean quickScan = false;

        @Parameter(names = {"--html-report", "-r"}, description = "Generate HTML report from last scan")
        private boolean generateReport = false;

        @Parameter(names = {"--context"}, description = "ZAP Context name to use (optional)")
        private String contextName;

        @Parameter(names = {"--policy"}, description = "ZAP Scan Policy name to use (optional)")
        private String policyName;

        @Parameter(names = {"--ci-mode"}, description = "Enable CI mode (non-zero exit if vulnerabilities found)")
        private boolean ciMode = false;

        @Parameter(names = {"--delta"}, description = "Enable delta reporting (compare with previous snapshot)")
        private boolean enableDelta = false;

        @Parameter(names = {"--help", "-h"}, help = true, description = "Show usage")
        private boolean help = false;
    }

    public static void main(String[] args) {
        CLIOptions options = new CLIOptions();
        JCommander commander = JCommander.newBuilder()
                .addObject(options)
                .programName("Security Strike Sentinel")
                .build();

        try {
            commander.parse(args);

            if (options.help || args.length == 0) {
                commander.usage();
                return;
            }

            if (options.zapTarget != null) {
                System.out.println("[+] Running ZAP scan on: " + options.zapTarget);
                if (options.quickScan) {
                    System.out.println("[i] Quick scan mode enabled (passive only)");
                }

                boolean failOnCvss = Boolean.parseBoolean(System.getProperty("fail.cvss", "false"));

                ZapScanner scanner = new ZapScanner(
                    options.contextName,
                    options.policyName,
                    true,                // Generate HTML
                    failOnCvss,          // Fail if high CVSS found
                    options.enableDelta  // Delta reporting
                );

                int findings = scanner.scan(options.zapTarget, options.quickScan);
                System.out.printf("[✓] ZAP scan completed. Findings: %d%n", findings);

                if (options.ciMode && findings > 0) {
                    System.err.println("[!] CI mode enabled: vulnerabilities found. Exiting with non-zero status.");
                    System.exit(1);
                }
            }

            if (options.generateReport) {
                System.out.println("[+] Generating HTML report...");
                Path jsonPath = Paths.get("reports/zap_result.json");

                if (Files.exists(jsonPath)) {
                    HtmlReportGenerator reportGen = new HtmlReportGenerator();
                    reportGen.generateDetailedReportFromJson(
                            options.zapTarget != null ? options.zapTarget : "Unknown Target",
                            jsonPath.toString()
                    );
                    System.out.println("[✓] HTML report generated successfully.");
                } else {
                    System.err.println("[!] No scan result JSON found. Run --zapscan first.");
                }
            }

        } catch (Exception e) {
            System.err.println("[!] Error: " + e.getMessage());
            commander.usage();
            e.printStackTrace();
        }
    }
}
