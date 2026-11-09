package com.ciberurjc.siem.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import tools.jackson.databind.DeserializationFeature;

import javax.sql.DataSource;

@Configuration
@Profile("persistence")
public class EventPersistenceConfiguration {
    @Bean
    JsonMapperBuilderCustomizer preserveDecimalEventDetails() {
        return builder -> builder.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    }

    @Bean(destroyMethod = "close")
    HikariDataSource dataSource(
            @Value("${siem.database.url}") String url,
            @Value("${siem.database.username}") String username,
            @Value("${siem.database.password}") String password) {
        HikariConfig configuration = new HikariConfig();
        configuration.setJdbcUrl(url);
        configuration.setUsername(username);
        configuration.setPassword(password);
        configuration.setMaximumPoolSize(5);
        configuration.setMinimumIdle(1);
        configuration.setConnectionTimeout(3000);
        return new HikariDataSource(configuration);
    }

    @Bean
    JdbcClient jdbcClient(DataSource dataSource) {
        return JdbcClient.create(dataSource);
    }
}
