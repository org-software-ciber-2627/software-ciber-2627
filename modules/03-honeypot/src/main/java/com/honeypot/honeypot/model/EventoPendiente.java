package com.honeypot.honeypot.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Evento que no ha llegado al SIEM y espera para reenviarse (HP-22).
 * Se guarda el JSON tal cual, porque el SIEM solo acepta un reenvío si es idéntico al original.
 */
@Entity
@Table(name = "eventos_pendientes")
public class EventoPendiente {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, length = 10000)
	private String json;

	// null si el evento no viene de un intento
	@Column(name = "attempt_id")
	private Long attemptId;

	@Column(nullable = false)
	private Instant creado;

	public EventoPendiente() {
	}

	public EventoPendiente(String json, Long attemptId) {
		this.json = json;
		this.attemptId = attemptId;
		this.creado = Instant.now();
	}

	public Long getId() {
		return id;
	}

	public String getJson() {
		return json;
	}

	public Long getAttemptId() {
		return attemptId;
	}

	public Instant getCreado() {
		return creado;
	}
}
