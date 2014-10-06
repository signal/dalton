#!/usr/bin/env python

from collections import defaultdict
import json
import yaml

def read(filename):
  with open(filename, 'r') as f:
    return json.loads(f.read())

def parse(security_groups):
  rules = defaultdict(list)
  for security_group_title, security_group in security_groups.iteritems():
    security_group_name, security_group_id, security_group_vpc_id = security_group_title.split(':')
    for rule_name, rule in security_group.iteritems():
      rules[security_group_name].extend([(rule["ip_protocol"], rule["from_port"], rule["to_port"], grant)
                                         for grant in rule["grants"]])
  return rules

def write(filename, rules):
  with open(filename, 'w') as f:
    f.write(yaml.safe_dump(rules, indent=12, default_flow_style=False))

def transform(security_groups):
  yaml_groups = {}
  for name, rules in security_groups.iteritems():
    yaml_groups[name] = {
      'options': {
        'description': name,
        'prune': True
      },
      'rules': ['%s port %s %s' % (ip_protocol, to_port if from_port == to_port else "%s-%s" % (from_port, to_port), grant)
                for ip_protocol, from_port, to_port, grant in rules]
    }
  return yaml_groups

REGIONS = ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1']

def main():
  for region in REGIONS:
    security_groups = parse(read('/tmp/serialized_rules_%s.json' % region))
    write('security_groups_%s.yaml' % region, transform(security_groups))

if __name__ == '__main__':
  main()
