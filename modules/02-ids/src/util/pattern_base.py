##Initialization of the patterns' state (enabled/disabled)

class PatternBase:
    def __init__(self):
        self.enabled = True

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False