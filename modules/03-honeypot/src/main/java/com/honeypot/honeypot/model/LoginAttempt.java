package com.honeypot.honeypot.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "login_attempts")
public class LoginAttempt {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "source_ip", length = 64)
	private String sourceIp;

	@Column(name = "occurred_at")
	private Instant occurredAt;

	@Column(name = "service_attacked", length = 64)
	private String serviceAttacked;

	@Column(length = 320)
	private String username;

	@Column(name = "credential_attempt", length = 2000)
	private String credentialAttempt;

	@Column(name = "password_length")
	private Integer passwordLength;

	@Column(name = "attempted_command", length = 2000)
	private String attemptedCommand;

	@Column(name = "request_path", length = 512)
	private String requestPath;

	@Column(name = "user_agent", length = 512)
	private String userAgent;

	@Column(name = "enviado",nullable = false, columnDefinition = "boolean default false")
	private boolean enviado = false;

	@Column(name = "tipo_ataque", length = 64)
	private String tipoAtaque;

	public LoginAttempt() {
	}

	public Long getId() {
		return id;
	}

	public String getSourceIp() {
		return sourceIp;
	}

	public Instant getOccurredAt() {
		return occurredAt;
	}

	public String getServiceAttacked() {
		return serviceAttacked;
	}

	public String getUsername() {
		return username;
	}

	public String getCredentialAttempt() {
		return credentialAttempt;
	}

	public Integer getPasswordLength() {
		return passwordLength;
	}

	public String getAttemptedCommand() {
		return attemptedCommand;
	}

	public String getRequestPath() {
		return requestPath;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	public void setOccurredAt(Instant occurredAt) {
		this.occurredAt = occurredAt;
	}

	public void setServiceAttacked(String serviceAttacked) {
		this.serviceAttacked = serviceAttacked;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public void setCredentialAttempt(String credentialAttempt) {
		this.credentialAttempt = credentialAttempt;
	}

	public void setPasswordLength(Integer passwordLength) {
		this.passwordLength = passwordLength;
	}

	public void setAttemptedCommand(String attemptedCommand) {
		this.attemptedCommand = attemptedCommand;
	}

	public void setRequestPath(String requestPath) {
		this.requestPath = requestPath;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public boolean isEnviado() {
		return enviado;
	}

	public void setEnviado(boolean enviado) {
		this.enviado = enviado;
	}

	public String getTipoAtaque() {
		return tipoAtaque;
	}

	public void setTipoAtaque(String tipoAtaque) {
		this.tipoAtaque = tipoAtaque;
	}
}