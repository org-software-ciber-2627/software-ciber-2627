import os
import re
from typing import Dict, List, Optional

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "ids.rules")
ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
EXTRA_ARG_REGEX = re.compile(r"^[A-Za-z0-9_]+=[A-Za-z0-9_.-]+$")


class RuleValidationError(Exception):
    """Error lanzado cuando una regla no cumple el formato o validación."""


class RuleManager:
    def __init__(self, rules_path: str = DEFAULT_RULES_PATH):
        self.rules_path = os.path.abspath(rules_path)
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
        if not os.path.exists(self.rules_path):
            header = (
                "# ==========================================\n"
                "# REGLAS DEL MOTOR\n"
                "# Formato: ID,UMBRAL,VENTANA_SEGUNDOS,ARGUMENTOS_EXTRA\n"
                "# ==========================================\n"
            )
            with open(self.rules_path, "w", encoding="utf-8") as f:
                f.write(header)

    def _read_lines(self) -> List[str]:
        with open(self.rules_path, "r", encoding="utf-8") as f:
            return f.readlines()

    def _write_lines(self, lines: List[str]) -> None:
        with open(self.rules_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    def get_existing_ids(self) -> List[str]:
        ids = []
        for raw_line in self._read_lines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if parts and parts[0]:
                ids.append(parts[0])
        return ids

    @staticmethod
    def parse_extra_args(extra_args: str) -> Dict[str, str]:
        if not extra_args or not extra_args.strip():
            return {}
        parsed: Dict[str, str] = {}
        for token in extra_args.strip().split(";"):
            token = token.strip()
            if not token:
                continue
            if not EXTRA_ARG_REGEX.match(token):
                raise RuleValidationError(
                    f"Argumento extra inválido '{token}'. Usa formato clave=valor (ej. usernames=3)."
                )
            key, value = token.split("=", 1)
            parsed[key] = value
        return parsed

    def validate_rule(
        self,
        rule_id: str,
        threshold: int | str,
        window: int | str,
        extra_args: str = "",
        check_duplicate: bool = True,
    ) -> str:
        """Valida los campos de una regla y devuelve la línea formateada lista para ids.rules."""
        clean_id = (rule_id or "").strip()
        if not ID_REGEX.match(clean_id):
            raise RuleValidationError(
                f"ID de regla inválido '{rule_id}'. Usa 2-32 caracteres alfanuméricos, '_' o '-'."
            )

        if check_duplicate and clean_id in self.get_existing_ids():
            raise RuleValidationError(f"Ya existe una regla con el ID '{clean_id}'.")

        try:
            threshold_int = int(str(threshold).strip())
        except ValueError as err:
            raise RuleValidationError("El umbral (UMBRAL) debe ser un número entero.") from err
        if threshold_int <= 0:
            raise RuleValidationError("El umbral (UMBRAL) debe ser mayor que 0.")

        try:
            window_int = int(str(window).strip())
        except ValueError as err:
            raise RuleValidationError("La ventana de segundos (VENTANA_SEGUNDOS) debe ser un entero.") from err
        if window_int <= 0:
            raise RuleValidationError("La ventana de segundos (VENTANA_SEGUNDOS) debe ser mayor que 0.")

        clean_extra = (extra_args or "").strip()
        if clean_extra:
            self.parse_extra_args(clean_extra)
            return f"{clean_id},{threshold_int},{window_int},{clean_extra}\n"

        return f"{clean_id},{threshold_int},{window_int}\n"

    def add_rule(
        self,
        rule_id: str,
        threshold: int | str,
        window: int | str,
        extra_args: str = "",
    ) -> str:
        """Valida y añade una nueva regla al final de ids.rules."""
        formatted_line = self.validate_rule(
            rule_id=rule_id,
            threshold=threshold,
            window=window,
            extra_args=extra_args,
            check_duplicate=True,
        )
        lines = self._read_lines()
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(formatted_line)
        self._write_lines(lines)
        return formatted_line.strip()

    def edit_rule(
        self,
        rule_id: str,
        threshold: int | str,
        window: int | str,
        extra_args: Optional[str] = None,
    ) -> str:
        """Edita una regla existente validando sus campos."""
        target_id = (rule_id or "").strip()
        lines = self._read_lines()
        updated = False
        new_lines: List[str] = []
        updated_line = ""

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(raw_line)
                continue

            parts = [p.strip() for p in stripped.split(",")]
            if parts[0] != target_id:
                new_lines.append(raw_line)
                continue

            previous_extra = parts[3] if len(parts) > 3 else ""
            chosen_extra = previous_extra if extra_args is None else (extra_args or "")

            validated = self.validate_rule(
                rule_id=target_id,
                threshold=threshold,
                window=window,
                extra_args=chosen_extra,
                check_duplicate=False,
            ).strip()

            ending = "\n" if raw_line.endswith("\n") else ""
            new_lines.append(f"{validated}{ending}")
            updated = True
            updated_line = validated

        if not updated:
            raise KeyError(f"No se encontró ninguna regla con ID '{target_id}' en {self.rules_path}")

        self._write_lines(new_lines)
        return updated_line

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> str:
        """Marca una regla como activa o desactivada en ids.rules sin borrarla."""
        target_id = (rule_id or "").strip()
        lines = self._read_lines()
        updated = False
        new_lines: List[str] = []

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(raw_line)
                continue

            parts = [p.strip() for p in stripped.split(",")]
            if parts[0] != target_id:
                new_lines.append(raw_line)
                continue

            updated = True
            rule_id_val = parts[0]
            threshold_val = parts[1] if len(parts) > 1 else "1"
            window_val = parts[2] if len(parts) > 2 else "60"
            extra_val = parts[3] if len(parts) > 3 else ""

            extra_dict = self.parse_extra_args(extra_val)
            extra_dict["enabled"] = "true" if enabled else "false"
            new_extra = ";".join(f"{k}={v}" for k, v in extra_dict.items())

            ending = "\n" if raw_line.endswith("\n") else ""
            new_lines.append(f"{rule_id_val},{threshold_val},{window_val},{new_extra}{ending}")

        if not updated:
            raise KeyError(f"No se encontró ninguna regla con ID '{target_id}' en {self.rules_path}")

        self._write_lines(new_lines)
        return target_id

    def disable_rule(self, rule_id: str) -> str:
        """Desactiva una regla existente."""
        return self.set_rule_enabled(rule_id, False)

    def enable_rule(self, rule_id: str) -> str:
        """Activa una regla existente."""
        return self.set_rule_enabled(rule_id, True)

    def is_rule_enabled_in_config(self, rule_id: str) -> Optional[bool]:
        """Devuelve True/False según ids.rules, o None si el ID no está en el fichero."""
        for raw_line in self._read_lines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = [p.strip() for p in stripped.split(",")]
            if parts[0] == rule_id:
                if len(parts) <= 3 or not parts[3]:
                    return True
                extra_dict = self.parse_extra_args(parts[3])
                if "enabled" not in extra_dict:
                    return True
                return extra_dict["enabled"].lower() in ("1", "true", "yes", "on", "enabled")
        return None