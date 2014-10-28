from pyparsing import CaselessKeyword, Literal, Word, StringEnd, Optional, Combine, Group, ParseException
from pyparsing import alphas, nums, alphanums, delimitedList

import yaml

from dalton.config.models import SecurityGroup, Rule


class YamlFileSecurityGroupsConfigLoader(object):
    """
    Loads SecurityGroups from a YAML configuration file.

    Format example:
      default:
        options:
          description: default group applied to all instances
          prune: true

        rules:
          - tcp port 0-65535 default                # Security Group with name 'default' to All TCP
          - udp port 0-65535 sg-123456              # Security Group with id 'sg-123456' to All UDP
          - icmp port 8 0.0.0.0/0                   # Anywhere to ICMP Type 8; Echo Request
          - tcp port 22 203.0.113.1                 # Chief's Home to SSH

      load-balancer:
        options:
          description: custom application server instances
          prune: false

        rules:
          - tcp port 80, 443 0.0.0.0/0              # Anywhere to HTTP/HTTPS
    """

    def __init__(self, yaml_path):
        self.yaml_path = yaml_path

    def load(self):
        with open(self.yaml_path, 'r') as f:
            configs = yaml.load(f.read())
            return self.parse_configs(configs)

    @classmethod
    def parse_configs(cls, security_group_configs):
        security_groups = {}
        for security_group_name, security_group_config in security_group_configs.iteritems():
            security_groups[security_group_name] = cls.parse_config(security_group_config)
        return security_groups

    @classmethod
    def parse_config(cls, security_group_config):
        options = security_group_config['options']
        rules = set(rule for rule_string in security_group_config.get('rules', []) for rule in RuleParser.parse(rule_string))
        return SecurityGroup(options['description'], rules, prune=options['prune'])


class RuleParser(object):
    """
    Responsible for parsing security group rules. Rules have the form
      <protocol:optional, default tcp> "port"(optional) (<security-group-id> | <security-group-name> | <ip-address-with-optional-mask>)

    See the test cases for examples of supported rules.
    """

    to_int                = lambda tokens: int(tokens[0])
    to_port_range         = lambda tokens: [(tokens[0].port, tokens[0].port)] if tokens[0].port or tokens[0].port==0 else [(tokens[0][0].port, tokens[0][1].port)]
    to_ipv4_prefix        = lambda instr, loc, tokens: int(tokens[0]) if int(tokens[0]) <= 32 else RuleParser.raises(ParseException(instr, loc, "%s is an invalid prefix length" % tokens[0]))
    to_octet              = lambda instr, loc, tokens: int(tokens[0]) if int(tokens[0]) <= 255 else RuleParser.raises(ParseException(instr, loc, "%s is an invalid octet" % tokens[0]))
    invalid_address       = lambda instr, loc, expr, err: RuleParser.raises(ParseException(instr, loc, "%s is an invalid IPv4 address: %s" % (instr, err)))

    protocol              = CaselessKeyword("tcp") ^ CaselessKeyword("udp") ^ CaselessKeyword("icmp")

    port                  = Group(Word(nums).setParseAction(to_int)('port'))
    port_range            = Group((port + Literal("-").suppress() + port))
    normalized_port_range = (port ^ port_range).setParseAction(to_port_range)
    ports                 = delimitedList(normalized_port_range)('ports')

    security_group_id     = Combine("sg-" + Word(alphanums, min=1))
    security_group_name   = Word(alphas, alphanums + "-._", min=1)

    octet                 = Word(nums, min=1, max=3).setParseAction(to_octet)
    ip_address            = Combine(octet + ('.' + octet)*3)
    ipv4_prefix           = Word(nums, min=1, max=2).setParseAction(to_ipv4_prefix)
    cidr_address          = ip_address + Literal('/').suppress() + ipv4_prefix
    ip_or_cidr_address    = ip_address.copy().setParseAction(lambda tokens: [tokens[0], 32]) ^ cidr_address
    normalized_address    = ip_or_cidr_address.setParseAction(lambda tokens: tokens[0] + '/' + str(tokens[1])).setFailAction(invalid_address)

    source                = normalized_address('address') ^ security_group_id('security_group_id') ^ security_group_name('security_group_name')
    parser = rule         = Optional(protocol, default="tcp")('protocol') + Optional(CaselessKeyword("port")) + ports + source + StringEnd()

    @classmethod
    def parse(cls, rule_string):
        """
        Parses a rule string into a list of rules.

        This may return multiple rules because multiple ports and ranges
        are supported in a single rule string.
        """
        result = cls.parser.parseString(rule_string)
        kwargs = {
            'address': result.address or None,
            'security_group_id': result.security_group_id or None,
            'security_group_name': result.security_group_name or None
        }
        return [Rule(result.protocol, from_port, to_port, **kwargs) for from_port, to_port in result.ports]

    @staticmethod
    def raises(exception):
        raise exception
