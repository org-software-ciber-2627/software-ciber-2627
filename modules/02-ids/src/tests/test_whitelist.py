from util.pattern_loader import patterns

P004 = patterns["P004"]
P005 = patterns["P005"]


def _scan_events(src, n=3):
    return [
        {
            "timestamp": f"Nov 20 10:00:{i:02d}",
            "source_ip": src,
            "destination_ip": f"10.0.0.{i + 1}",
            "destination_port": 22,
        }
        for i in range(n)
    ]


def _failed_logins(src, n=3):
    return [
        {
            "timestamp": f"Nov 20 10:00:{i:02d}",
            "event_type": "failed_login",
            "source_ip": src,
            "username": "root",
            "service": "ssh",
        }
        for i in range(n)
    ]


def _rule(monkeypatch, cls, whitelist):
    monkeypatch.setattr(cls, "whitelist", whitelist)
    return cls(threshold="3", window="60")


def test_ip_interna_no_genera_deteccion(monkeypatch):
    rule = _rule(monkeypatch, P005, ["192.168.1.0/24"])
    assert rule.run(_scan_events("192.168.1.50")) == []


def test_ip_externa_con_mismo_patron_si_genera_deteccion(monkeypatch):
    rule = _rule(monkeypatch, P005, ["192.168.1.0/24"])
    assert len(rule.run(_scan_events("203.0.113.9"))) == 1


def test_ip_suelta_en_whitelist(monkeypatch):
    rule = _rule(monkeypatch, P005, ["127.0.0.1"])
    assert rule.run(_scan_events("127.0.0.1")) == []


def test_cidr_cubre_todo_el_rango(monkeypatch):
    rule = _rule(monkeypatch, P005, ["10.0.0.0/8"])
    assert rule.run(_scan_events("10.200.3.4")) == []


def test_fuerza_bruta_interna_se_ignora(monkeypatch):
    rule = _rule(monkeypatch, P004, ["192.168.1.0/24"])
    assert rule.run(_failed_logins("192.168.1.77")) == []


def test_fuerza_bruta_externa_se_detecta(monkeypatch):
    rule = _rule(monkeypatch, P004, ["192.168.1.0/24"])
    assert len(rule.run(_failed_logins("203.0.113.9"))) == 1


def test_whitelist_vacia_no_filtra_nada(monkeypatch):
    rule = _rule(monkeypatch, P005, [])
    assert len(rule.run(_scan_events("192.168.1.50"))) == 1


def test_entrada_invalida_no_rompe_y_las_validas_siguen_funcionando(monkeypatch):
    rule = _rule(monkeypatch, P005, ["esto-no-es-una-ip", "192.168.1.0/24"])
    assert rule.run(_scan_events("192.168.1.50")) == []


def test_ip_invalida_en_el_evento_no_revienta(monkeypatch):
    rule = _rule(monkeypatch, P005, ["192.168.1.0/24"])
    assert rule._in_whitelist("no-es-ip") is False


def test_whitelist_como_texto_separado_por_comas(monkeypatch):
    rule = _rule(monkeypatch, P005, "127.0.0.1, 192.168.1.0/24")
    assert rule.run(_scan_events("192.168.1.50")) == []