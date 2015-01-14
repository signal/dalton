import unittest

from nose.tools import assert_sequence_equal, raises
from pyparsing import ParseException

from dalton.config.loader import RuleParser
from dalton.config.models import Rule


class RuleParsingTest(unittest.TestCase):
    all_tcp = Rule(protocol="tcp", from_port=0, to_port=65535, security_group_name="default")
    http_server = Rule(protocol="tcp", from_port=80, to_port=80, address="0.0.0.0/0")
    https_server = Rule(protocol="tcp", from_port=443, to_port=443, address="0.0.0.0/0")
    app_server1 = Rule(protocol="tcp", from_port=8000, to_port=8100, address="0.0.0.0/0")
    app_server2 = Rule(protocol="tcp", from_port=9000, to_port=9100, address="0.0.0.0/0")
    single_address = Rule(protocol="tcp", from_port=0, to_port=65535, address="1.2.3.4/32")
    cassandra = [
        Rule(protocol="tcp", from_port=7000, to_port=7001, security_group_name="cassandra"),
        Rule(protocol="tcp", from_port=7199, to_port=7199, security_group_name="cassandra"),
        Rule(protocol="tcp", from_port=61620, to_port=61621, security_group_name="cassandra")
    ]

    def test_address_single_port(self):
        assert_sequence_equal([self.http_server], RuleParser.parse("tcp port 80 0.0.0.0/0"))

    @raises(ParseException)
    def test_address_single_port_trailing_comma(self):
        RuleParser.parse("tcp port 80, 1.2.3.4")

    def test_address_multiple_ports(self):
        assert_sequence_equal([self.http_server, self.https_server], RuleParser.parse("tcp port 80,443 0.0.0.0/0"))

    def test_address_multiple_ports_ignores_whitespace(self):
        assert_sequence_equal([self.http_server, self.https_server], RuleParser.parse("tcp port 80, 443 0.0.0.0/0"))

    def test_address_port_range(self):
        assert_sequence_equal([self.app_server1], RuleParser.parse("tcp port 8000-8100 0.0.0.0/0"))

    def test_address_port_range_multiple_ports(self):
        expected = [self.http_server, self.https_server, self.app_server1]
        assert_sequence_equal(expected, RuleParser.parse("tcp port 80, 443, 8000-8100 0.0.0.0/0"))

    def test_address_multiple_port_ranges(self):
        assert_sequence_equal([self.app_server1, self.app_server2], RuleParser.parse("tcp port 8000-8100, 9000-9100 0.0.0.0/0"))

    @raises(ParseException)
    def test_address_invalid_octet(self):
        RuleParser.parse("tcp port 80 1.2.3.256")

    @raises(ParseException)
    def test_address_invalid_prefix_length(self):
        RuleParser.parse("tcp port 80 1.2.3.4/38")

    def test_group_name(self):
        assert_sequence_equal([self.all_tcp], RuleParser.parse("tcp port 0-65535 default"))

    def test_group_name_includes_dot(self):
        expected = Rule(protocol="tcp", from_port=80, to_port=80, security_group_name="web.group")
        assert_sequence_equal([expected], RuleParser.parse("tcp port 80 web.group"))

    @raises(ParseException)
    def test_group_name_starts_with_dot(self):
        RuleParser.parse("tcp port 80 .my_group")

    def test_group_name_multiple_ports(self):
        expected = [
            Rule(protocol="tcp", from_port=22,   to_port=22,   security_group_name="default"),
            Rule(protocol="tcp", from_port=2812, to_port=2812, security_group_name="default"),
            Rule(protocol="tcp", from_port=4001, to_port=4001, security_group_name="default"),
        ]
        assert_sequence_equal(expected, RuleParser.parse("tcp port 22, 2812, 4001 default"))

    def test_group_name_port_range(self):
        expected = Rule(protocol="tcp", from_port=61620, to_port=61621, security_group_name="cassandra")
        assert_sequence_equal([expected], RuleParser.parse("tcp port 61620-61621 cassandra"))

    def test_group_name_multiple_ports_port_ranges(self):
        assert_sequence_equal(self.cassandra, RuleParser.parse("tcp port 7000-7001,7199, 61620-61621 cassandra"))

    def test_group_id(self):
        expected = Rule(protocol="tcp", from_port=0, to_port=65535, security_group_id="sg-12345")
        assert_sequence_equal([expected], RuleParser.parse("tcp port 0-65535 sg-12345"))

    def test_tcp_default(self):
        assert_sequence_equal([self.all_tcp], RuleParser.parse("port 0-65535 default"))

    def test_port_keyword_optional(self):
        assert_sequence_equal([self.all_tcp], RuleParser.parse("tcp 0-65535 default"))

    def test_tcp_default_and_port_keyword_optional(self):
        assert_sequence_equal([self.all_tcp], RuleParser.parse("0-65535 default"))

    def test_tcp_default_and_port_keyword_optional_multiple_ports_and_port_ranges(self):
        assert_sequence_equal(self.cassandra, RuleParser.parse("7000-7001, 7199,61620-61621 cassandra"))

    def test_address_with_mask(self):
        assert_sequence_equal([self.single_address], RuleParser.parse("tcp port 0-65535 1.2.3.4/32"))

    def test_address_mask_defaults_to_32(self):
        assert_sequence_equal([self.single_address], RuleParser.parse("tcp port 0-65535 1.2.3.4"))

    def test_udp(self):
        expected = Rule(protocol="udp", from_port=2003, to_port=2003, address="1.2.3.4/29")
        assert_sequence_equal([expected], RuleParser.parse("udp port 2003 1.2.3.4/29"))

    def test_icmp(self):
        expected = [
            Rule(protocol="icmp", from_port=0,  to_port=0,  security_group_name="default"),
            Rule(protocol="icmp", from_port=3,  to_port=5,  security_group_name="default"),
            Rule(protocol="icmp", from_port=8,  to_port=14, security_group_name="default"),
            Rule(protocol="icmp", from_port=40, to_port=40, security_group_name="default")
        ]
        assert_sequence_equal(expected, RuleParser.parse("icmp port 0, 3-5, 8-14, 40 default"))

    @raises(ParseException)
    def test_unknown_protocol(self):
        RuleParser.parse("dccp port 9 0.0.0.0/0")

    @raises(ParseException)
    def test_unparsable_port(self):
        RuleParser.parse("tcp port mail 0.0.0.0/0")

    @raises(ParseException)
    def test_invalid_cidr(self):
        assert_sequence_equal([], RuleParser.parse("tcp port 80 0.0.0.0//0"))

    @raises(ParseException)
    def test_invalid_mask(self):
        RuleParser.parse("tcp port 80 0.0.0.0/zz")

    def test_protocol_is_case_insensitive(self):
        expected = Rule(protocol="udp", from_port=2003, to_port=2003, address="1.2.3.4/29")
        assert_sequence_equal([expected], RuleParser.parse("UDP port 2003 1.2.3.4/29"))

    def test_port_is_case_insensitive(self):
        assert_sequence_equal([self.http_server], RuleParser.parse("tcp PORT 80 0.0.0.0/0"))

    # @raises(ParseException)
    # def test_mask_with_whitespace(self):
    #     assert_sequence_equal([],
    #                           RuleParser.parse("tcp port 80 1.2.3.4 / 29"))
