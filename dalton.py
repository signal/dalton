#!/usr/bin/env python
"""
Dalton manages your security groups.

Usage:
  dalton <environment> <region>
  dalton -h | --help
  dalton --version

Options:
  --version             Show version.
  -h --help             Show this screen.
"""

from boto.ec2 import connect_to_region
from docopt import docopt
from roadhouse.group import SecurityGroupsConfig
import yaml

def main(env, region):
  credentials = yaml.load(open('config/aws.yaml', 'r').read())[env]
  ec2 = connect_to_region(region, **credentials)
  config = SecurityGroupsConfig.load("config/%(env)s/security_groups_%(region)s.yaml" % {'env':env,'region':region})
  config.configure(ec2)
  config.apply()

if __name__ == '__main__':
  options = docopt(__doc__, version='Dalton 0.1.0')
  main(options['<environment>'], options['<region>'])
