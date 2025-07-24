package com.securitystrikesentinel.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ZapAuthManager {

    private static final String ZAP_BASE = "http://localhost:8080";
    private static final String API_KEY = "1utjr8dcvt4521ujk7d62md5l9";

    private final String contextName;
    private final String username;
    private final String password;
    private final String authMethod;
    private final String loginUrl;
    private final String loggedInIndicator;
    private final String logoutIndicator;
    private final String authExclude;


    public ZapAuthManager(
            String contextName,
            String username,
            String password,
            String authMethod,
            String loginUrl,
            String loggedInIndicator,
            String logoutIndicator,
            String authExclude
    ) {
        this.contextName = contextName;
        this.username = username;
        this.password = password;
        this.authMethod = authMethod;
        this.loginUrl = loginUrl;
        this.loggedInIndicator = loggedInIndicator;
        this.logoutIndicator = logoutIndicator;
        this.authExclude = authExclude;
    }

    public String getContextName() {
        return contextName;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public String getLoginUrl() {
        return loginUrl;
    }

    public String getLoggedInIndicator() {
        return loggedInIndicator;
    }

    public String getLogoutIndicator() {
        return logoutIndicator;
    }

    public String getAuthExclude() {
        return authExclude;
    }

    /**
     * Configures authentication in ZAP, including dynamic context creation if needed.
     *
     * @param contextName Name of the ZAP context to use or create.
     * @param targetUrl   Target base URL (e.g., http://example.com).
     * @throws IOException if API interaction fails.
     */
    public void configureAuthentication(String contextName, String targetUrl) throws IOException {
        System.out.printf("[Auth] Initializing authentication setup for context: %s%n", contextName);

        // Step 0: Check if context exists
        String checkContext = ZAP_BASE + "/JSON/context/view/contextList/?apikey=" + API_KEY;
        String contextListJson = send(checkContext);
        JsonNode contextList = new ObjectMapper().readTree(contextListJson).path("contextList");

        boolean contextExists = false;
        for (JsonNode ctx : contextList) {
            if (ctx.asText().equals(contextName)) {
                contextExists = true;
                break;
            }
        }

        if (!contextExists) {
            System.out.printf("[+] Context '%s' not found. Creating it now...%n", contextName);
            String createContext = String.format(
                    "%s/JSON/context/action/newContext/?contextName=%s&apikey=%s",
                    ZAP_BASE,
                    URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                    API_KEY
            );
            send(createContext);
        }

        // Step 1: Set authentication method (form-based login)
        String loginUrl = targetUrl + "/login";
        String loginPostData = "username={%username%}&password={%password%}";

        String setAuthMethod = String.format(
                "%s/JSON/authentication/action/setAuthenticationMethod/?contextName=%s&authMethodName=formBasedAuthentication&authMethodConfigParams=loginUrl=%s&loginRequestData=%s&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                URLEncoder.encode(loginUrl, StandardCharsets.UTF_8),
                URLEncoder.encode(loginPostData, StandardCharsets.UTF_8),
                API_KEY
        );
        send(setAuthMethod);

        // Step 2: Set login indicator (this must match your app's successful login)
        String setIndicator = String.format(
                "%s/JSON/authentication/action/setLoggedInIndicator/?contextName=%s&loggedInIndicatorRegex=Welcome&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                API_KEY
        );
        send(setIndicator);

        // Step 3: Create and configure user
        String createUser = String.format(
                "%s/JSON/users/action/newUser/?contextName=%s&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                API_KEY
        );
        String userIdJson = send(createUser);
        String userId = new ObjectMapper().readTree(userIdJson).path("userId").asText();

        String setCreds = String.format(
                "%s/JSON/users/action/setAuthenticationCredentials/?contextName=%s&userId=%s&authCredentialsConfigParams=username=%s&password=%s&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                userId,
                URLEncoder.encode(username, StandardCharsets.UTF_8),
                URLEncoder.encode(password, StandardCharsets.UTF_8),
                API_KEY
        );
        send(setCreds);

        String enableUser = String.format(
                "%s/JSON/users/action/setUserEnabled/?contextName=%s&userId=%s&enabled=true&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                userId,
                API_KEY
        );
        send(enableUser);

        // Step 4: Force ZAP to use this user during scanning
        send(String.format(
                "%s/JSON/forcedUser/action/setForcedUser/?contextName=%s&userId=%s&apikey=%s",
                ZAP_BASE,
                URLEncoder.encode(contextName, StandardCharsets.UTF_8),
                userId,
                API_KEY
        ));

        send(String.format(
                "%s/JSON/forcedUser/action/setForcedUserModeEnabled/?boolean=true&apikey=%s",
                ZAP_BASE,
                API_KEY
        ));

        System.out.println("[✓] ZAP authentication + context configuration complete.");
    }


    private String send(String urlStr) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Accept", "application/json");

        BufferedReader reader = new BufferedReader(new InputStreamReader(
                conn.getResponseCode() < 400 ? conn.getInputStream() : conn.getErrorStream()
        ));

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) response.append(line);
        reader.close();
        return response.toString();
    }
}
