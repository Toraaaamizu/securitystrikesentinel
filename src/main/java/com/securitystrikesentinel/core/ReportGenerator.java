package com.securitystrikesentinel.core;

import java.io.IOException;

/**
 * Defines a contract for generating reports in various formats.
 */
public interface ReportGenerator {

    /**
     * Generates a report based on the given scan data.
     *
     * @param target        the target that was scanned
     * @param findingsCount total number of findings
     * @param jsonPath      optional JSON file path with detailed findings
     * @throws IOException if report generation fails
     */
    void generateReport(String target, int findingsCount, String jsonPath) throws IOException;

    /**
     * @return the type of report generated, e.g. "HTML", "JSON"
     */
    String getType();
}
