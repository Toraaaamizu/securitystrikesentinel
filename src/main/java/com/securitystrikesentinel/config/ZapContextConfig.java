package com.securitystrikesentinel.config;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZapContextConfig {

    @JsonProperty("contextName")
    public String contextName;

    @JsonProperty("includeRegex")
    public String includeRegex;

    @JsonProperty("excludeRegex")
    public String excludeRegex;

    @JsonProperty("sessionManagement")
    public String sessionManagement;

    @JsonProperty("authentication")
    public Authentication authentication;

    @JsonProperty("users")
    public List<User> users;

    @JsonProperty("useForcedUser")
    public boolean useForcedUser;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Authentication {
        @JsonProperty("type")
        public String type;

        @JsonProperty("loginUrl")
        public String loginUrl;

        @JsonProperty("loginRequest")
        public String loginRequest;

        @JsonProperty("indicatorRegex")
        public String indicatorRegex;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class User {
        @JsonProperty("name")
        public String name;

        @JsonProperty("credentials")
        public Map<String, String> credentials;
    }

    public static ZapContextConfig loadFromFile(String jsonPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(new File(jsonPath), ZapContextConfig.class);
    }
}
