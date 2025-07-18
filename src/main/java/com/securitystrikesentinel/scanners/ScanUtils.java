package com.securitystrikesentinel.scanners;

public class ScanUtils {
    public static boolean isValidUrl(String url) {
        return url != null && url.startsWith("http");
    }
}