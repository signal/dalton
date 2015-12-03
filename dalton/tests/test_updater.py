import unittest

from pymock import *

from dalton.config import Rule
from dalton.updater import SecurityGroupUpdater

class FakeSecurityGroup(object):
    def __init__(self, id, name):
        self.id, self.name = id, name

class SecurityGroupUpdaterTest(PyMockTestCase):
    def test_update_security_group_rules_authorize_rules(self, vpc=None):
        service = self.mock()
        sg1, sg2 = FakeSecurityGroup('sg1-id', 'sg1-name'), FakeSecurityGroup('sg2-id', 'sg2-name')
        security_group, data_center, dry_run = 'load-balancer', 'us-east-1', False
        required_group_rules = frozenset([
            Rule(protocol="tcp", from_port=80,  to_port=80,  address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=443, to_port=443, address="0.0.0.0/0")
        ])
        updater = SecurityGroupUpdater(service)
        self.expectAndReturn(service.get_permissions(security_group, data_center, vpc), frozenset())
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        service.authorize_ingress_rules(security_group, required_group_rules, data_center, vpc, dry_run)
        self.replay()
        updater.update_security_group_rules(security_group, required_group_rules, data_center, vpc)
        self.verify()

    def test_update_security_group_rules_authorize_rules_in_vpc(self):
        self.test_update_security_group_rules_authorize_rules(vpc="brettifer")

    def test_update_security_group_rules_revoke_rules(self, vpc=None):
        service = self.mock()
        sg1, sg2 = FakeSecurityGroup('sg1-id', 'sg1-name'), FakeSecurityGroup('sg2-id', 'sg2-name')
        security_group, data_center, vpc, dry_run = 'load-balancer', 'us-east-1', None, False
        current_group_rules = frozenset([
            Rule(protocol="tcp", from_port=80,  to_port=80,  address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=443, to_port=443, address="0.0.0.0/0")
        ])
        updater = SecurityGroupUpdater(service)
        self.expectAndReturn(service.get_permissions(security_group, data_center, vpc), current_group_rules)
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        service.revoke_ingress_rules(security_group, current_group_rules, data_center, vpc, dry_run)
        self.replay()
        updater.update_security_group_rules(security_group, frozenset(), data_center, dry_run=dry_run)
        self.verify()

    def test_update_security_group_rules_revoke_rules_in_vpc(self):
        self.test_update_security_group_rules_revoke_rules(vpc="konkolnafulous")


    def test_update_security_group_rules_authorize_and_revoke_rules(self, vpc=None):
        service = self.mock()
        sg1, sg2 = FakeSecurityGroup('sg1-id', 'sg1-name'), FakeSecurityGroup('sg2-id', 'sg2-name')
        security_group, data_center, vpc, dry_run = 'load-balancer', 'us-east-1', None, False
        current_group_rules = frozenset([
            Rule(protocol="tcp", from_port=80,   to_port=80,   address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=443,  to_port=443,  address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=8000, to_port=8000, address="0.0.0.0/0")
        ])
        required_group_rules = frozenset([
            Rule(protocol="tcp", from_port=80,   to_port=80,  address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=443,  to_port=443, address="0.0.0.0/0"),
            Rule(protocol="tcp", from_port=22,   to_port=22,  address="0.0.0.0/0")
        ])
        rules_to_add = frozenset([
            Rule(protocol="tcp", from_port=22,   to_port=22,  address="0.0.0.0/0"),
        ])
        rules_to_remove = frozenset([
            Rule(protocol="tcp", from_port=8000, to_port=8000, address="0.0.0.0/0")
        ])
        updater = SecurityGroupUpdater(service)
        self.expectAndReturn(service.get_permissions(security_group, data_center, vpc), current_group_rules)
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        self.expectAndReturn(service.get_all(data_center, vpc), [sg1, sg2])
        service.authorize_ingress_rules(security_group, rules_to_add, data_center, vpc, dry_run)
        service.revoke_ingress_rules(security_group, rules_to_remove, data_center, vpc, dry_run)
        self.replay()
        updater.update_security_group_rules(security_group, required_group_rules, data_center)
        self.verify()

    def test_update_security_group_rules_authorize_and_revoke_rules_in_vpc(self):
        self.test_update_security_group_rules_authorize_and_revoke_rules(vpc="jusbus")
