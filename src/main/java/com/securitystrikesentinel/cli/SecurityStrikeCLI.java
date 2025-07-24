package com.securitystrikesentinel.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.securitystrikesentinel.auth.ZapAuthManager;
import com.securitystrikesentinel.reports.HtmlReportGenerator;
import com.securitystrikesentinel.scanners.zap.ZapScanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SecurityStrikeCLI {

    @Parameter(names = {"--zapscan", "-z"}, description = "Run ZAP scan on the specified target URL")
    private String zapTarget;

    @Parameter(names = {"--quick"}, description = "Run passive scan only (quick mode)")
    private boolean quickScan = false;

    @Parameter(names = {"--context"}, description = "ZAP Context name (optional)")
    private String context;

    @Parameter(names = {"--policy"}, description = "Scan policy to use (Default: 'Default Policy')")
    private String scanPolicy;

    @Parameter(names = {"--ci"}, description = "Enable CI/CD mode (fail build on high severity issues)")
    private boolean ciMode;

    @Parameter(names = {"--delta"}, description = "Enable delta reporting (compare with previous scan)")
    private boolean enableDelta;

    @Parameter(names = {"--html-report", "-r"}, description = "Generate HTML report from last JSON result")
    private boolean generateReport;

    @Parameter(names = {"--auth-method"}, description = "ZAP authentication method (form/manual/http)")
    private String authMethod;

    @Parameter(names = {"--auth-login-url"}, description = "Login URL for authentication")
    private String authLoginUrl;

    @Parameter(names = {"--auth-username"}, description = "Username for login")
    private String authUsername;

    @Parameter(names = {"--auth-password"}, description = "Password for login")
    private String authPassword;

    @Parameter(names = {"--auth-logged-in-indicator"}, description = "Pattern or keyword indicating login success")
    private String loggedInIndicator;

    @Parameter(names = {"--auth-logout-indicator"}, description = "Pattern or keyword indicating logout")
    private String logoutIndicator;

    @Parameter(names = {"--auth-exclude"}, description = "Regex pattern to exclude from authentication")
    private String authExclude;

    @Parameter(names = {"--help", "-h"}, help = true, description = "Show this help message")
    private boolean help;

    public static void main(String... args) {
        SecurityStrikeCLI cli = new SecurityStrikeCLI();
        JCommander jc = JCommander.newBuilder()
                .addObject(cli)
                .programName("Security Strike Sentinel")
                .build();

        try {
            jc.parse(args);

            if (cli.help || args.length == 0) {
                jc.usage();
                return;
            }

            if (cli.zapTarget != null) {
                System.out.println("[+] Launching ZAP scan on: " + cli.zapTarget);
                if (cli.quickScan) System.out.println("[i] Quick (passive) scan mode enabled");
                if (cli.ciMode) System.out.println("[i] CI/CD mode: will fail on high severity issues");
                if (cli.enableDelta) System.out.println("[i] Delta comparison enabled");

                // Suggest default context if not set but auth is provided
                if (cli.context == null && cli.authMethod != null) {
                    System.out.println("[?] Context not provided. Suggest using '--context default-context'");
                    cli.context = "default-context";
                }

                ZapAuthManager authManager = null;
                if (cli.authMethod != null) {
                    authManager = new ZapAuthManager(
                            cli.context != null ? cli.context : "default-context",
                            cli.authMethod,
                            cli.authLoginUrl,
                            cli.authUsername,
                            cli.authPassword,
                            cli.loggedInIndicator,
                            cli.logoutIndicator,
                            cli.authExclude
                    );
                    System.out.printf("[✓] Auth configured for user: %s%n", cli.authUsername);
                }

                ZapScanner scanner = new ZapScanner(
                        cli.context,
                        cli.scanPolicy != null ? cli.scanPolicy : "Default Policy",
                        !cli.ciMode,   // generate HTML only outside CI
                        cli.ciMode,    // fail on vuln only in CI
                        cli.enableDelta,
                        authManager
                );

                int findings = scanner.scan(cli.zapTarget, cli.quickScan);
                System.out.printf("[✓] Scan complete. Total findings: %d%n", findings);

                if (cli.ciMode && findings > 0) {
                    System.err.println("[!] CI/CD: vulnerabilities found. Failing with exit code 1.");
                    System.exit(1);
                }
            }

            if (cli.generateReport) {
                System.out.println("[+] Generating HTML report from last scan...");
                Path jsonPath = Paths.get("reports/zap_result.json");

                if (Files.exists(jsonPath)) {
                    HtmlReportGenerator generator = new HtmlReportGenerator();
                    generator.generateDetailedReportFromJson(
                            cli.zapTarget != null ? cli.zapTarget : "Unknown Target",
                            jsonPath.toString()
                    );
                    System.out.println("[✓] HTML report generated successfully.");
                } else {
                    System.err.println("[!] No scan result found. Run with --zapscan first.");
                }
            }

        } catch (Exception e) {
            System.err.println("[!] Error: " + e.getMessage());
            jc.usage();
            e.printStackTrace();
        }
    }
}
