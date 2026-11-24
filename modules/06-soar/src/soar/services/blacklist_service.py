import ipaddress
import logging
import os
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel

from soar.models.blacklist_entry import BlacklistEntry
from soar.repositories.blacklist_repository import BlacklistRepository, DuplicateIpError

logger = logging.getLogger("soar")

BLOCKED = "blocked"
ALREADY_BLOCKED = "already_blocked"
INVALID_IP = "invalid_ip"
EXCLUDED = "excluded"

# Redes que nunca se bloquean, además de la IP no especificada (0.0.0.0 y ::)
ALWAYS_EXCLUDED_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
EXCLUDED_NETWORKS_ENV = "BLACKLIST_EXCLUDED_NETWORKS"

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class BlockResult(BaseModel):
    """
    Resultado de BlacklistService.block. HU19.2 lo convierte en success / failed / skipped.
    entry es la entrada nueva (blocked), la original (already_blocked) o None (invalid_ip, excluded).
    """

    outcome: Literal["blocked", "already_blocked", "invalid_ip", "excluded"]
    ip: Optional[str] = None
    entry: Optional[BlacklistEntry] = None
    message: str


def parse_excluded_networks(raw: Optional[str]) -> list[IpNetwork]:
    """
    Lee una lista de redes separadas por comas. Una red mal escrita se ignora con un WARNING.
    """
    networks = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Red ignorada en %s, no es válida: %r", EXCLUDED_NETWORKS_ENV, item)
    return networks


class BlacklistService:
    def __init__(
        self,
        repository: BlacklistRepository,
        clock: Optional[Callable[[], datetime]] = None,
        excluded_networks: Optional[Iterable[str]] = None,
    ) -> None:
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        raw = ",".join(excluded_networks) if excluded_networks is not None else os.getenv(EXCLUDED_NETWORKS_ENV)
        self._excluded = [*ALWAYS_EXCLUDED_NETWORKS, *parse_excluded_networks(raw)]

    def block(self, ip: Any, incident_id: str, reason: str) -> BlockResult:
        address = self._parse_ip(ip)
        if address is None:
            return BlockResult(outcome=INVALID_IP, message=f"IP no válida: {ip!r}")

        normalized = str(address)
        if self._is_excluded(address):
            return BlockResult(outcome=EXCLUDED, ip=normalized, message=f"La IP {normalized} no se puede bloquear")

        existing = self._repository.get_by_ip(normalized)
        if existing is not None:
            return self._already_blocked(existing)

        entry = BlacklistEntry(ip=normalized, incident_id=incident_id, added_at=self._clock(), reason=reason)
        try:
            self._repository.add(entry)
        except DuplicateIpError:
            # Otro proceso la ha bloqueado entre la consulta y el alta
            return self._already_blocked(self._repository.get_by_ip(normalized))
        logger.info("IP %s añadida a la lista negra (incidente %s)", normalized, incident_id)
        return BlockResult(outcome=BLOCKED, ip=normalized, entry=entry, message=f"IP {normalized} bloqueada")

    def list_blacklist(self) -> list[BlacklistEntry]:
        return sorted(self._repository.list_all(), key=lambda entry: entry.added_at)

    @staticmethod
    def _parse_ip(ip: Any) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        if not isinstance(ip, str) or not ip.strip():
            return None
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        # ::ffff:1.2.3.4 se trata como la IPv4 1.2.3.4
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return address.ipv4_mapped
        return address

    def _is_excluded(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if address.is_unspecified:
            return True
        return any(address.version == network.version and address in network for network in self._excluded)

    @staticmethod
    def _already_blocked(entry: Optional[BlacklistEntry]) -> BlockResult:
        ip = entry.ip if entry else None
        return BlockResult(outcome=ALREADY_BLOCKED, ip=ip, entry=entry, message=f"La IP {ip} ya estaba bloqueada")
