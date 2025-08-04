package com.securitystrikesentinel.reports;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.file.*;
import java.util.List;

public class CsvReportWriter {

    public static void writeCsv(String jsonPath, String outputPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(new File(jsonPath));
        JsonNode alerts = root.path("alerts");

        if (!alerts.isArray()) throw new IOException("Invalid ZAP alerts format.");

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(outputPath))) {
            writer.write("Alert,Risk,URL,Description\n");

            for (JsonNode alert : alerts) {
                String name = sanitize(alert.path("alert").asText());
                String risk = sanitize(alert.path("risk").asText());
                String url = sanitize(alert.path("url").asText());
                String desc = sanitize(alert.path("description").asText()).replaceAll("[\\r\\n]+", " ");

                writer.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\"\n", name, risk, url, desc));
            }
        }
    }

    private static String sanitize(String value) {
        return value.replace("\"", "\"\"");
    }
}
