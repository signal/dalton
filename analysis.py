#!/usr/bin/env python
"""
Runs an analysis on your EC2 Security Group instance assignments.
"""

from boto.ec2 import connect_to_region
import re
import yaml
from time import time
from cachetools import ttl_cache
from flask import Flask, render_template

REGIONS = ['us-east-1','us-west-1','eu-west-1','ap-northeast-1','us-west-2']

DIGIT = re.compile("\d")
UNDERSCORE = re.compile("_")

@ttl_cache(ttl=5*60)
def get_all_reservations(ec2):
    return ec2.get_all_reservations()

def fetch_records(env):
  credentials = yaml.load(open('config/aws.yaml', 'r').read())[env]

  records = []
  for region in REGIONS:
    ec2 = connect_to_region(region, **credentials)
    for reservation in get_all_reservations(ec2):
      if len(reservation.instances) > 1:
        print "More than one instance in this reservation: %s" % reservation.id
        continue

      instance = reservation.instances[0]
      name = instance.tags.get('Name', instance.id)
      groups = [group.name for group in reservation.groups]

      m = DIGIT.search(name)
      role = name[0:m.start()] if m else "unknown"

      if "default" not in groups:
        print "%s missing default group" % name
      groups = [group for group in groups if group != "default"]

      has_correct_roles = len(groups) > 0
      for group in groups:
        if group.startswith("cassandra_"):
          m = UNDERSCORE.search(group)
          g = group[m.start()+1:len(group)] if m else group
        else:
          g = "graph" if group == "graphite" else group
        has_correct_roles = has_correct_roles and role == g
      records.append([region, role, name, groups, has_correct_roles])
  return records

app = Flask(__name__)

@app.route('/')
@app.route('/<env>')
def security_group_assignments(env='prod'):
  records = fetch_records(env)
  return render_template('assignments.html', records=records)

if __name__ == '__main__':
  app.run(debug=True)

