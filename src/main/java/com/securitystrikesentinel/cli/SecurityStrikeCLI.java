package com.securitystrikesentinel.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.securitystrikesentinel.auth.ZapAuthManager;
import com.securitystrikesentinel.scanners.zap.ZapScanner;

public class SecurityStrikeCLI {

    public static class CLIOptions {

        @Parameter(names = {"--zapscan", "-z"}, description = "Run ZAP scan on target")
        private String zapTarget;

        @Parameter(names = {"--quick"}, description = "Run passive-only (quick) scan")
        private boolean quickScan = false;

        @Parameter(names = {"--html-report"}, description = "Generate HTML report")
        private boolean htmlReport = false;

        @Parameter(names = {"--csv-report"}, description = "Generate CSV report")
        private boolean csvReport = false;

        @Parameter(names = {"--context"}, description = "Context name to use")
        private String context;

        @Parameter(names = {"--policy"}, description = "ZAP Scan Policy to use")
        private String policy;

        @Parameter(names = {"--ci"}, description = "Fail build on high vulnerabilities")
        private boolean ciMode = false;

        @Parameter(names = {"--auth-username"})
        private String authUsername;

        @Parameter(names = {"--auth-password"})
        private String authPassword;

        @Parameter(names = {"--auth-method"})
        private String authMethod;

        @Parameter(names = {"--auth-login-url"})
        private String loginUrl;

        @Parameter(names = {"--auth-username-field"})
        private String usernameField;

        @Parameter(names = {"--auth-password-field"})
        private String passwordField;

        @Parameter(names = {"--auth-logout-indicator"})
        private String logoutIndicator;

        @Parameter(names = {"--auth-logged-in-indicator"})
        private String loggedInIndicator;

        @Parameter(names = {"--auth-exclude"})
        private String authExclude;

        @Parameter(names = {"--help", "-h"}, help = true, description = "Show help")
        private boolean help;
    }

    public static void main(String[] args) throws Exception {
        CLIOptions options = new CLIOptions();
        JCommander jc = JCommander.newBuilder().addObject(options).build();
        jc.parse(args);

        if (options.help || options.zapTarget == null) {
            jc.usage();
            return;
        }

        ZapAuthManager authManager = null;
        if (options.authUsername != null && options.authPassword != null && options.authMethod != null) {
            authManager = new ZapAuthManager(
                    options.context != null ? options.context : "default-context",
                    options.authUsername,
                    options.authPassword,
                    options.authMethod,
                    options.loginUrl,
                    options.usernameField,
                    options.passwordField,
                    options.logoutIndicator,
                    options.loggedInIndicator,
                    options.authExclude
            );
        }

        ZapScanner scanner = new ZapScanner(
                options.context,
                options.policy,
                options.htmlReport,
                options.ciMode,
                false,
                authManager,
                options.csvReport
        );

        int findings = scanner.scan(options.zapTarget, options.quickScan, -1, -1);
        System.out.printf("[✓] ZAP scan finished with %d findings.%n", findings);
    }
} 