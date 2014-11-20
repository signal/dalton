#!/usr/bin/env python
"""
Runs an analysis on your EC2 Security Group instance assignments.
"""

from boto.ec2 import connect_to_region
import re
import yaml
from cachetools import ttl_cache
from flask import Flask, render_template

REGIONS = ['us-east-1','us-west-1','eu-west-1','ap-northeast-1','us-west-2']

DIGIT = re.compile("\d")
UNDERSCORE = re.compile("_")

@ttl_cache(ttl=5*60)
def get_all_reservations(ec2):
  return ec2.get_all_reservations()

def fetch_hosts_and_groups(env):
  credentials = yaml.load(open('config/aws.yaml', 'r').read())[env]

  records = []
  for region in REGIONS:
    ec2 = connect_to_region(region, **credentials)
    for reservation in get_all_reservations(ec2):
      if len(reservation.instances) > 1:
        print "Skipping reservation with more than one instance: %s" % reservation.id
        continue

      instance = reservation.instances[0]
      name = instance.tags.get('Name', instance.id)
      groups = [group.name for group in reservation.groups]

      m = DIGIT.search(name)
      role = name[0:m.start()] if m else "unknown"

      records.append([region, role, name, groups])
  return records

def analyze_security_group_assignments(records):
  analyzed = []
  for region, role, name, groups in records:
    if "default" not in groups:
      print "%s missing default group" % name
    groups = [group for group in groups if group != "default"]
    has_correct_groups = check_has_correct_security_groups(role, groups)
    analyzed.append([region, role, name, groups, has_correct_groups])
  return analyzed

def check_has_correct_security_groups(role, security_groups):
  has_correct_groups = len(security_groups) > 0
  for group in security_groups:
    if group.startswith("cassandra_"):
      m = UNDERSCORE.search(group)
      g = group[m.start()+1:len(group)] if m else group
    else:
      g = "graph" if group == "graphite" else group
    has_correct_groups = has_correct_groups and role == g
  return has_correct_groups

app = Flask(__name__)

@app.route('/')
@app.route('/<env>')
def security_group_assignments(env='prod'):
  records = analyze_security_group_assignments(fetch_hosts_and_groups(env))
  return render_template('assignments.html', records=records)

if __name__ == '__main__':
  app.run(debug=True)
