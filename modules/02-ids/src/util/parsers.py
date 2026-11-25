from util.pattern_loader import patterns


# Returns a tuple of configured pattern instances
def parse_rules(rule_path) -> tuple:
    rules: list = []
    with open(rule_path, 'r') as rule_file:
        # Read each line in the file
        for line in rule_file:
            line = line.strip()
            # Ignore comments in rules file
            if not line or line.startswith("#"): continue
            # Obtain pattern ID and arguments per rule
            pattern_id, *rule_args = line.split(",")
            pattern_cls = patterns[pattern_id]
            # Obtain keyword arguments if present
            rule_kwargs = dict([arg.split("=") for arg in rule_args if "=" in arg])
            rule_args = [arg for arg in rule_args if "=" not in arg]
            rules.append(pattern_cls(*rule_args, **rule_kwargs))

    # Return configured instances of the patterns
    return tuple(rules)
