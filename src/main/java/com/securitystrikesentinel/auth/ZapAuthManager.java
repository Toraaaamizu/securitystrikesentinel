package com.securitystrikesentinel.auth;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

public class ZapAuthManager {

    private final String contextName;
    private final String authMethod;
    private final String loginUrl;
    private final String username;
    private final String password;
    private final String usernameField;
    private final String passwordField;
    private final String loggedInIndicator;
    private final String logoutIndicator;
    private final String authExclude;

    private static final String ZAP_API_BASE = "http://localhost:8080/JSON";

    public ZapAuthManager(
            String contextName,
            String authMethod,
            String loginUrl,
            String username,
            String password,
            String usernameField,
            String passwordField,
            String loggedInIndicator,
            String logoutIndicator,
            String authExclude
    ) {
        this.contextName = contextName;
        this.authMethod = authMethod;
        this.loginUrl = loginUrl;
        this.username = username;
        this.password = password;
        this.usernameField = usernameField;
        this.passwordField = passwordField;
        this.loggedInIndicator = loggedInIndicator;
        this.logoutIndicator = logoutIndicator;
        this.authExclude = authExclude;
    }

    public void configureAuthentication(String contextName, String targetUrl) {
        if (!isZapAvailable()) {
            System.err.println("[!] ZAP not available. Skipping authentication configuration.");
            return;
        }

        try {
            System.out.printf("[Auth] Setting up auth for context: %s (method: %s)%n", contextName, authMethod);

            // Create context
            callZap("/context/action/newContext/", "contextName=" + encode(contextName));

            // Set form-based auth method
            String authParams = String.format("loginUrl=%s&loginRequestData=%s=%s&%s=%s",
                    encode(loginUrl),
                    encode(usernameField), encode(username),
                    encode(passwordField), encode(password)
            );

            callZap("/authentication/action/setAuthenticationMethod/", String.format(
                    "contextName=%s&authMethodName=%s&authMethodConfigParams=%s",
                    encode(contextName), encode(authMethod), authParams
            ));

            // Add user
            String userJson = callZap("/users/action/newUser/", "contextName=" + encode(contextName));
            String userId = userJson.replaceAll("[^0-9]", "");

            callZap("/users/action/setAuthenticationCredentials/", String.format(
                    "contextName=%s&userId=%s&authCredentialsConfigParams=username=%s&password=%s",
                    encode(contextName), userId, encode(username), encode(password)
            ));

            callZap("/users/action/setUserEnabled/", String.format(
                    "contextName=%s&userId=%s&enabled=true",
                    encode(contextName), userId
            ));

            // Set logged-in indicator (optional)
            if (loggedInIndicator != null && !loggedInIndicator.isBlank()) {
                callZap("/authentication/action/setLoggedInIndicator/", String.format(
                        "contextName=%s&loggedInIndicatorRegex=%s",
                        encode(contextName), encode(loggedInIndicator)
                ));
            }

            // Set logged-out indicator (optional)
            if (logoutIndicator != null && !logoutIndicator.isBlank()) {
                callZap("/authentication/action/setLoggedOutIndicator/", String.format(
                        "contextName=%s&loggedOutIndicatorRegex=%s",
                        encode(contextName), encode(logoutIndicator)
                ));
            }

            // Exclude from auth (optional)
            if (authExclude != null && !authExclude.isBlank()) {
                callZap("/authentication/action/excludeFromAuthentication/", String.format(
                        "contextName=%s&regex=%s",
                        encode(contextName), encode(authExclude)
                ));
            }

            System.out.println("[✓] Authentication configured successfully.");

        } catch (Exception e) {
            System.err.println("[!] Failed to configure authentication: " + e.getMessage());
        }
    }

    private boolean isZapAvailable() {
        try {
            URL url = new URL(ZAP_API_BASE + "/core/view/version/");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            return conn.getResponseCode() == 200;
        } catch (IOException e) {
            return false;
        }
    }

    private String callZap(String path, String query) throws IOException {
        URL url = new URL(ZAP_API_BASE + path + "?" + query);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        if (conn.getResponseCode() != 200) {
            throw new IOException("Failed to call ZAP API: " + url);
        }
        return new String(conn.getInputStream().readAllBytes());
    }

    private String encode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }

    // Getters (if needed)
    public String getContextName() {
        return contextName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
