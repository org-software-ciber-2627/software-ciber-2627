import importlib
import pkgutil

import patterns as patterns_ns
from util.config_loader import config

# ID of pattern and class for all detected patterns
patterns: dict = {}


# Wrapper that configures a pattern
def pattern(pattern_id: str, name: str, risk: str):
    def wrapper(cls):
        cls.pattern_id = pattern_id
        cls.name = name
        cls.risk = risk
        # Config loading
        cls.log_file = config["LOGFILE"]
        cls.whitelist = config["WHITELIST"]
        global patterns
        patterns[pattern_id] = cls
        return cls

    return wrapper


def reload_patterns() -> None:
    # Imports all modules in the patterns_ns namespace
    for _, name, _ in pkgutil.iter_modules(patterns_ns.__path__, patterns_ns.__name__ + "."):
        importlib.import_module(name)


reload_patterns()
