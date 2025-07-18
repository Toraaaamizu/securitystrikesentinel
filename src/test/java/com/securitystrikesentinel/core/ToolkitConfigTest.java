package com.securitystrikesentinel.core;
import org.junit.jupiter.api.Test;           // ✅ JUnit 5
import static org.junit.jupiter.api.Assertions.*; // ✅ JUnit 5 Assertions
import com.securitystrikesentinel.core.ToolkitConfig;
public class ToolkitConfigTest {
    @Test
    public void testReportDirConstant() {
        assertEquals("reports", ToolkitConfig.REPORT_DIR);
    }
}