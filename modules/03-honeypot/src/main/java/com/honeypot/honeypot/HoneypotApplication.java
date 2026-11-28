package com.honeypot.honeypot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling // Reintento de eventos pendientes (HP-22)
public class HoneypotApplication {

	public static void main(String[] args) {
		SpringApplication.run(HoneypotApplication.class, args);
	}

}