package com.securitystrikesentinel.scanners;
import org.junit.jupiter.api.Test;

import com.securitystrikesentinel.scanners.zap.ScanUtils;

import static org.junit.jupiter.api.Assertions.*;

public class ScanUtilsTest {
    @Test
    public void testValidUrl() {
        assertTrue(ScanUtils.isValidUrl("http://example.com"));
        assertFalse(ScanUtils.isValidUrl("ftp://example.com"));
    }
}