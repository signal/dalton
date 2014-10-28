import unittest

from nose.tools import assert_equal, assert_not_equal
from dalton.config.models import Rule

class RuleTest(unittest.TestCase):
    sg = Rule(protocol='tcp', from_port=8000, to_port=8100, address="0.0.0.0/0")

    def test_equals_self(self):
        self.assert_objects_and_hashes_equal(self.sg, self.sg)

    def test_equals_identical(self):
        other = Rule(protocol='tcp', from_port=8000, to_port=8100, address="0.0.0.0/0")
        self.assert_objects_and_hashes_equal(self.sg, other)

    def test_not_equals_protocol_differs(self):
        other = Rule(protocol='udp', from_port=8080, to_port=8100, address="0.0.0.0/0")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_from_port_differs(self):
        other = Rule(protocol='tcp', from_port=8001, to_port=8100, address="0.0.0.0/0")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_to_port_differs(self):
        other = Rule(protocol='tcp', from_port=8000, to_port=8101, address="0.0.0.0/0")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_address_differs(self):
        other = Rule(protocol='tcp', from_port=8000, to_port=8100, address="1.2.3.4/32")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_security_group_id_differs(self):
        other = Rule(protocol='tcp', from_port=8000, to_port=8100, address="0.0.0.0/0", security_group_id="sg-1234")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def test_not_equals_security_group_name_differs(self):
        other = Rule(protocol='tcp', from_port=8000, to_port=8100, address="0.0.0.0/0", security_group_name="default")
        self.assert_objects_and_hashes_not_equal(self.sg, other)

    def assert_objects_and_hashes_equal(self, obj1, obj2):
        assert_equal(obj1, obj2)
        assert_equal(obj2, obj1)
        assert_equal(hash(obj1), hash(obj2))

    def assert_objects_and_hashes_not_equal(self, obj1, obj2):
        assert_not_equal(obj1, obj2)
        assert_not_equal(obj2, obj1)
        assert_not_equal(hash(obj1), hash(obj2))
