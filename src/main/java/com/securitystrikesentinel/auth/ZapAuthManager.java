package com.securitystrikesentinel.auth;

import java.util.Map;
import java.util.logging.Logger;

import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

/**
 * Handles ZAP context-based authentication setup and user management.
 */
public class ZapAuthManager {

    private static final Logger LOGGER = Logger.getLogger(ZapAuthManager.class.getName());
    private final ClientApi api;
    private final String contextName;
    private int contextId = -1;

    public ZapAuthManager(ClientApi api, String contextName) {
        this.api = api;
        this.contextName = contextName;
    }

    /**
     * Initializes a ZAP context and returns its ID.
     */
    public int initContext() throws ClientApiException {
        LOGGER.info("Creating ZAP context: " + contextName);
        this.contextId = Integer.parseInt(new String(api.context.newContext(contextName)));
        return contextId;
    }

    /**
     * Configures form-based authentication.
     */
    public void configureFormAuth(String loginUrl, String loginRequestData) throws ClientApiException {
        LOGGER.info("Setting form-based authentication...");
        api.authentication.setAuthenticationMethod(
            Integer.toString(contextId),
            "formBasedAuthentication",
            "loginUrl=" + loginUrl + "&loginRequestData=" + loginRequestData
        );
    }

    /**
     * Adds a user with given credentials.
     */
    public int createUser(String username, String password) throws ClientApiException {
        LOGGER.info("Creating user in context ID " + contextId);
        String userJson = new String(api.users.newUser(Integer.toString(contextId), username));
        int userId = Integer.parseInt(userJson.replaceAll("[^0-9]", ""));
        
        String credentials = "username=" + username + "&password=" + password;
        api.users.setAuthenticationCredentials(Integer.toString(contextId), Integer.toString(userId), credentials);
        api.users.setUserEnabled(Integer.toString(contextId), Integer.toString(userId), "true");

        return userId;
    }

    /**
     * Forces ZAP to use the specified user for scanning.
     */
    public void setForcedUser(int userId) throws ClientApiException {
        LOGGER.info("Forcing user mode with user ID: " + userId);
        api.forcedUser.setForcedUser(Integer.toString(contextId), Integer.toString(userId));
        api.forcedUser.setForcedUserModeEnabled(true);
    }

    /**
     * Optional: disables forced user mode
     */
    public void disableForcedUser() throws ClientApiException {
        api.forcedUser.setForcedUserModeEnabled(false);
        LOGGER.info("Forced user mode disabled.");
    }

    public int getContextId() {
        return contextId;
    }

    public String getContextName() {
        return contextName;
    }
}
