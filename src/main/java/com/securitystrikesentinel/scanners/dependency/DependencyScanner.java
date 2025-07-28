package com.securitystrikesentinel.scanners.dependency;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Logger;
public class DependencyScanner {
    private static final Logger logger = Logger.getLogger(DependencyScanner.class.getName());

    public static void runDependencyCheck() throws IOException, InterruptedException {
        // Path to your local Maven executable
        String mvnPath = "C:\\apache-maven-3.9.11\\bin\\mvn.cmd";

        // Build the Maven dependency-check command
        ProcessBuilder pb = new ProcessBuilder(mvnPath, "dependency-check:check");
        pb.redirectErrorStream(true); // Combine error and output streams

        // Start the process
        Process process = pb.start();

        // Read output
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        Files.createDirectories(Paths.get("reports"));
        BufferedWriter writer = new BufferedWriter(new FileWriter("reports/depcheck_output.log"));

        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line); // Optional: display output
            writer.write(line);
            writer.newLine();
        }
        writer.close();

        // Wait for completion
        int exitCode = process.waitFor();
        logger.info("Dependency check finished with exit code: " + exitCode);
        logger.info("Dependency-Check log saved to reports/depcheck_output.log");
    }
}