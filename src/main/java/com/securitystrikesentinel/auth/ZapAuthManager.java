package com.securitystrikesentinel.auth;

/**
 * Manages ZAP authentication context and credentials.
 * Used to inject auth details into scans and optionally handle ZAP API calls for login.
 */
public class ZapAuthManager {

    private final String contextName;
    private final String username;
    private final String password;

    /**
     * Constructs an authentication manager with the provided context and credentials.
     *
     * @param contextName ZAP context name to use
     * @param username    Username for authentication
     * @param password    Password for authentication
     */
    public ZapAuthManager(String contextName, String username, String password) {
        this.contextName = contextName;
        this.username = username;
        this.password = password;
    }

    /**
     * @return ZAP context name
     */
    public String getContextName() {
        return contextName;
    }

    /**
     * @return Authenticated username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return Authenticated password
     */
    public String getPassword() {
        return password;
    }

    /**
     * This method should perform login/auth setup in ZAP via the API.
     * You can extend this to import contexts, set forced users, or perform script-based login.
     */
    public void performLoginLogic() {
        // TODO: Add ZAP API calls to import context, set credentials, start forced user mode etc.
        System.out.printf("[i] (Mock) Login initiated for context '%s' with user '%s'%n", contextName, username);

        // Example (future):
        // - /JSON/context/action/importContext/
        // - /JSON/authentication/action/setAuthenticationMethod/
        // - /JSON/users/action/setAuthenticationCredentials/
        // - /JSON/forcedUser/action/setForcedUser/
        // - /JSON/forcedUser/action/setForcedUserModeEnabled/
    }
}
