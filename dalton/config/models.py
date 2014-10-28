from dalton.equality import EqualityMixin

class Rule(EqualityMixin):
    """
    Represents a Security Group Rule.
    """

    def __init__(self, protocol, from_port, to_port, address=None, security_group_id=None, security_group_name=None):
        self.protocol = protocol
        self.from_port = from_port
        self.to_port = to_port
        self.address = address
        self.security_group_id = security_group_id
        self.security_group_name = security_group_name

    def __str__(self):
        port = "%d-%d" % (self.from_port, self.to_port) if self.from_port != self.to_port else self.from_port
        source = self.address or self.security_group_name or self.security_group_id
        return "%s port %s %s" % (self.protocol, port, source)


class SecurityGroup(EqualityMixin):
    """
    Represents a Security Group Configuration.
    """

    def __init__(self, description, rules, prune=False):
        self.description = description
        self._rules = frozenset(rules) # so SecurityGroup is hashable
        self.prune = prune

    @property
    def rules(self):
        return self._rules

    @rules.setter
    def rules(self, value):
        self._rules = frozenset(value)