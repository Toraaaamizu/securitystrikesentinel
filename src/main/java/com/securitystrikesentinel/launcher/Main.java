package com.securitystrikesentinel.launcher;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.securitystrikesentinel.auth.ZapAuthManager;
import com.securitystrikesentinel.reports.HtmlReportGenerator;
import com.securitystrikesentinel.scanners.zap.ZapScanner;

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

        @Parameter(names = {"--auth-username"}, description = "Username for authentication")
        private String authUsername;

        @Parameter(names = {"--auth-password"}, description = "Password for authentication")
        private String authPassword;

        @Parameter(names = {"--auth-method"}, description = "Auth method (form/manual/http)")
        private String authMethod;

        @Parameter(names = {"--auth-login-url"}, description = "Login URL")
        private String authLoginUrl;

        @Parameter(names = {"--auth-logged-in-indicator"}, description = "Regex/Indicator that shows login success")
        private String loggedInIndicator;

        @Parameter(names = {"--auth-logout-indicator"}, description = "Regex/Indicator for logout")
        private String logoutIndicator;

        @Parameter(names = {"--auth-username-field"}, description = "Username input field name")
        private String usernameField;

        @Parameter(names = {"--auth-password-field"}, description = "Password input field name")
        private String passwordField;

        @Parameter(names = {"--auth-exclude"}, description = "Regex pattern to exclude from auth")
        private String authExclude;

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
                if (options.quickScan) System.out.println("[i] Quick scan mode enabled");
                if (options.contextName != null) System.out.println("[i] Using context: " + options.contextName);
                if (options.policyName != null) System.out.println("[i] Scan policy: " + options.policyName);
                if (options.ciMode) System.out.println("[i] CI mode active");
                if (options.enableDelta) System.out.println("[i] Delta reporting enabled");

                boolean failOnVuln = options.ciMode || Boolean.parseBoolean(System.getProperty("fail.cvss", "false"));

                ZapAuthManager authManager = null;
                if (
                    options.authUsername != null && options.authPassword != null &&
                    options.authMethod != null && options.authLoginUrl != null &&
                    options.usernameField != null && options.passwordField != null
                ) {
                    authManager = new ZapAuthManager(
                            options.contextName != null ? options.contextName : "default-context",
                            options.authUsername,
                            options.authPassword,
                            options.authMethod,
                            options.authLoginUrl,
                            options.usernameField,
                            options.passwordField,
                            options.logoutIndicator,
                            options.loggedInIndicator,
                            options.authExclude
                    );

                    System.out.printf("[✓] Auth configured for user '%s' using method '%s'%n",
                            options.authUsername, options.authMethod);
                }

                ZapScanner scanner = new ZapScanner(
                        options.contextName,
                        options.policyName,
                        true,               // Generate HTML always
                        failOnVuln,
                        options.enableDelta,
                        authManager
                );

                int findings = scanner.scan(options.zapTarget, options.quickScan);
                System.out.printf("[✓] ZAP scan completed. Findings: %d%n", findings);

                if (options.ciMode && findings > 0) {
                    System.err.println("[!] CI mode: vulnerabilities found. Exiting with non-zero status.");
                    System.exit(1);
                }
            }

            if (options.generateReport) {
                System.out.println("[+] Generating HTML report...");
                Path jsonPath = Paths.get("reports/zap_result.json");

                if (Files.exists(jsonPath)) {
                    HtmlReportGenerator generator = new HtmlReportGenerator();
                    generator.generateDetailedReportFromJson(
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
            e.printStackTrace();
            commander.usage();
        }
    }
}
