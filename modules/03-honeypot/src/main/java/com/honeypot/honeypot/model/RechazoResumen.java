package com.honeypot.honeypot.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;

/**
 * Resumen de las peticiones rechazadas por el limitador (HP-88).
 * Una fila por IP, minuto y servicio, con el número de rechazos de ese minuto.
 */
@Entity
@Table(name = "rechazos_resumen",
		uniqueConstraints = @UniqueConstraint(columnNames = {"ip", "minuto", "servicio"}))
public class RechazoResumen {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(length = 64, nullable = false)
	private String ip;

	// Inicio del minuto (segundos a cero)
	@Column(nullable = false)
	private Instant minuto;

	@Column(length = 64, nullable = false)
	private String servicio;

	@Column(nullable = false)
	private int rechazos;

	public RechazoResumen() {
	}

	public RechazoResumen(String ip, Instant minuto, String servicio) {
		this.ip = ip;
		this.minuto = minuto;
		this.servicio = servicio;
		this.rechazos = 0;
	}

	public void sumarRechazo() {
		rechazos++;
	}

	public Long getId() {
		return id;
	}

	public String getIp() {
		return ip;
	}

	public Instant getMinuto() {
		return minuto;
	}

	public String getServicio() {
		return servicio;
	}

	public int getRechazos() {
		return rechazos;
	}
}
