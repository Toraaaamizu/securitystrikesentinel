package com.securitystrikesentinel.scanners.base;

/**
 * A generic interface for all types of security scanners (e.g., ZAP, Dependency Check).
 */
public interface Scanner {

    /**
     * Initiates a security scan against the given target.
     *
     * @param target URL or path to scan.
     * @throws Exception if scanning fails.
     */
    void scan(String target) throws Exception;

    /**
     * Returns the name of the scanner (e.g., "ZAP", "DependencyCheck").
     *
     * @return scanner name
     */
    String getName();
}
