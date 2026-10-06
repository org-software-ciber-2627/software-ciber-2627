package com.ciberurjc.siem.models;

public record Alert(
    String id,
    String timestamp,
    String severidad,
    String origen,
    String descripcion,
    String ipAtacante
) {}