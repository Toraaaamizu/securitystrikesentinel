package com.securitystrikesentinel.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.securitystrikesentinel.reports.HtmlReportGenerator;
import com.securitystrikesentinel.scanners.zap.ZapScanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SecurityStrikeCLI {

    @Parameter(names = {"--zapscan", "-z"}, description = "Run ZAP scan on target")
    private String zapTarget;

    @Parameter(names = {"--quick"}, description = "Run passive scan only (no active attack)")
    private boolean quickScan = false;

    @Parameter(names = {"--context"}, description = "Context name to load before scanning")
    private String context;

    @Parameter(names = {"--policy"}, description = "Custom scan policy to apply")
    private String scanPolicy;

    @Parameter(names = {"--ci"}, description = "Enable CI/CD mode (non-interactive, headless, minimal reporting)")
    private boolean ciMode;

    @Parameter(names = {"--delta"}, description = "Enable delta reporting (compare with previous snapshot)")
    private boolean enableDelta;

    @Parameter(names = {"--html-report", "-r"}, description = "Generate HTML report from last scan")
    private boolean generateReport;

    @Parameter(names = {"--help", "-h"}, help = true, description = "Display help message", order = 1)
    private boolean help;
    @Parameter(names = "--auth-method", description = "ZAP authentication method (manual, form, http)")
    private String authMethod;

    @Parameter(names = "--auth-login-url", description = "Login URL (for form or manual auth)")
    private String authLoginUrl;

    @Parameter(names = "--auth-username", description = "Username for authentication")
    private String authUsername;

    @Parameter(names = "--auth-password", description = "Password for authentication")
    private String authPassword;

    @Parameter(names = "--auth-logged-in-indicator", description = "Regex/Indicator to confirm user is logged in")
    private String loggedInIndicator;

    @Parameter(names = "--auth-logout-indicator", description = "Regex/Indicator that shows the user is logged out")
    private String logoutIndicator;

    @Parameter(names = "--auth-exclude", description = "Regex pattern of URLs to exclude from authentication")
    private String authExclude;

    public static void main(String... argv) {
        SecurityStrikeCLI cli = new SecurityStrikeCLI();
        JCommander jc = JCommander.newBuilder()
                .addObject(cli)
                .programName("Security Strike Sentinel")
                .build();

        try {
            jc.parse(argv);

            if (cli.help || argv.length == 0) {
                jc.usage();
                return;
            }

            if (cli.zapTarget != null) {
                System.out.println("[+] Starting ZAP scan on: " + cli.zapTarget);
                if (cli.quickScan) {
                    System.out.println("[i] Quick scan mode enabled (passive scan only)");
                }
                if (cli.context != null) {
                    System.out.println("[i] Using context: " + cli.context);
                }
                if (cli.scanPolicy != null) {
                    System.out.println("[i] Using custom scan policy: " + cli.scanPolicy);
                }
                if (cli.ciMode) {
                    System.out.println("[i] CI/CD mode enabled");
                }
                if (cli.enableDelta) {
                    System.out.println("[i] Delta reporting enabled");
                }
                if (cli.authMethod != null) {
                    System.out.printf("[i] Using authentication method: %s%n", cli.authMethod);
                    System.out.printf("[i] Login URL: %s%n", cli.authLoginUrl);
                    System.out.printf("[i] Username: %s%n", cli.authUsername);
                }


                ZapScanner scanner = new ZapScanner(
                        cli.context,
                        cli.scanPolicy,
                        !cli.ciMode,       // Generate HTML if not in CI
                        cli.ciMode,        // Fail on findings in CI mode
                        cli.enableDelta    // Enable delta report
                );

                int findings = scanner.scan(cli.zapTarget, cli.quickScan);
                System.out.printf("[✓] Scan complete. Total findings: %d%n", findings);

                if (cli.ciMode && findings > 0) {
                    System.err.println("[!] CI/CD mode: vulnerabilities found. Exiting with code 1.");
                    System.exit(1);
                }
            }

            if (cli.generateReport) {
                System.out.println("[+] Generating HTML report...");
                Path jsonPath = Paths.get("reports/zap_result.json");

                if (Files.exists(jsonPath)) {
                    HtmlReportGenerator generator = new HtmlReportGenerator();
                    generator.generateDetailedReportFromJson(
                            cli.zapTarget != null ? cli.zapTarget : "Unknown Target",
                            jsonPath.toString()
                    );
                    System.out.println("[✓] Report generated successfully.");
                } else {
                    System.err.println("[!] No scan result found. Please run a scan first using --zapscan.");
                }
            }

        } catch (Exception e) {
            System.err.println("[!] Error occurred: " + e.getMessage());
            e.printStackTrace();
            jc.usage();
        }
    }
}
