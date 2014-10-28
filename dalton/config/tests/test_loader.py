import unittest

from nose.tools import assert_equal

from dalton.config.loader import YamlFileSecurityGroupsConfigLoader
from dalton.config.models import Rule, SecurityGroup
from dalton.config.tests.fixtures import default_group, load_balancer_group


class YamlFileSecurityGroupsConfigLoaderTest(unittest.TestCase):
    default_group = SecurityGroup('default group applied to all instances', {
        Rule(protocol="tcp",  from_port=0,  to_port=65535, security_group_name="default"),
        Rule(protocol="udp",  from_port=0,  to_port=65535, security_group_id="sg-123456"),
        Rule(protocol="icmp", from_port=8,  to_port=8,     address="0.0.0.0/0"),
        Rule(protocol="tcp",  from_port=22, to_port=22,    address="203.0.113.1/32"),
    }, prune=True)

    load_balancer_group = SecurityGroup('custom application server instances', {
        Rule(protocol="tcp", from_port=80,  to_port=80,  address="0.0.0.0/0"),
        Rule(protocol="tcp", from_port=443, to_port=443, address="0.0.0.0/0")
    }, prune=False)

    def test_parse_config(self):
        assert_equal(self.default_group, YamlFileSecurityGroupsConfigLoader.parse_config(default_group))

    def test_parse_configs(self):
        configs = self.configs_from(default_group, load_balancer_group)
        expected = self.configs_from(self.default_group, self.load_balancer_group)
        assert_equal(expected, YamlFileSecurityGroupsConfigLoader.parse_configs(configs))

    def configs_from(self, default_group, load_balancer_group):
        return {
            'default': default_group,
            'load-balancer': load_balancer_group
        }
