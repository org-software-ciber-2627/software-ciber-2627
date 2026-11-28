package com.honeypot.honeypot.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class IdentidadProperties {

    private final String url;
    private final String serviceUser;
    private final String servicePassword;
    private final long refreshMarginSeconds;

    public IdentidadProperties(
            @Value("${identidad.url:http://identidad:80}") String url,
            @Value("${identidad.service.user:svc-honeypot}") String serviceUser,
            @Value("${identidad.service.password:}") String servicePassword,
            @Value("${identidad.token.refresh-margin-seconds:120}") long refreshMarginSeconds) {
        this.url = url;
        this.serviceUser = serviceUser;
        this.servicePassword = servicePassword;
        this.refreshMarginSeconds = refreshMarginSeconds;
    }

    public String getUrl() {
        return url;
    }

    public String getServiceUser() {
        return serviceUser;
    }

    public String getServicePassword() {
        return servicePassword;
    }

    public long getRefreshMarginSeconds() {
        return refreshMarginSeconds;
    }

    @Override
    public String toString() {
        return "IdentidadProperties{" +
                "url='" + url + '\'' +
                ", serviceUser='" + serviceUser + '\'' +
                ", servicePassword='****'" +
                ", refreshMarginSeconds=" + refreshMarginSeconds +
                '}';
    }
}
