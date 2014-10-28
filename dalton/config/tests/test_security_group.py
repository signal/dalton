import unittest

from nose.tools import assert_equal, assert_not_equal
from dalton.config.models import SecurityGroup

from dalton.config.tests.fixtures import default_group, load_balancer_group

class SecurityGroupTest(unittest.TestCase):
    sg = SecurityGroup(default_group['options']['description'], default_group['rules'], prune=default_group['options']['prune'])

    def test_equals_self(self):
        self.assert_objects_and_hashes_equal(self.sg, self.sg)

    def test_equals_identical(self):
        other = SecurityGroup(default_group['options']['description'], default_group['rules'], prune=default_group['options']['prune'])
        self.assert_objects_and_hashes_equal(self.sg, other)

    def test_not_equals_description_differs(self):
        other = SecurityGroup(load_balancer_group['options']['description'], default_group['rules'], prune=default_group['options']['prune'])
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_rules_differ(self):
        other = SecurityGroup(default_group['options']['description'], load_balancer_group['rules'], prune=default_group['options']['prune'])
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_prune_differs(self):
        other = SecurityGroup(default_group['options']['description'], default_group['rules'], prune=load_balancer_group['options']['prune'])
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_hashable_after_rules_changed(self):
        sg = SecurityGroup(default_group['options']['description'], default_group['rules'], prune=default_group['options']['prune'])
        sg.rules = load_balancer_group['rules']
        assert_equal(hash(sg), hash(sg))

    def assert_objects_and_hashes_equal(self, obj1, obj2):
        assert_equal(obj1, obj2)
        assert_equal(obj2, obj1)
        assert_equal(hash(obj1), hash(obj2))

    def assert_objects_and_hashes_not_equal(self, obj1, obj2):
        assert_not_equal(obj1, obj2)
        assert_not_equal(obj2, obj1)
        assert_not_equal(hash(obj1), hash(obj2))
