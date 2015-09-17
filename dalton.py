#!/usr/bin/env python
"""
Dalton manages your security groups.

Usage:
  dalton [-d | --dry-run] <environment> <region>
  dalton -h | --help
  dalton --version

Options:
  -d --dry-run          Performs a "dry run" to show (but not perform) security group changes
  --version             Show version.
  -h --help             Show this screen.
"""

from logging import basicConfig, getLogger, CRITICAL, INFO

from docopt import docopt
import yaml

from dalton.config import YamlFileSecurityGroupsConfigLoader
from dalton.ec2 import Ec2SecurityGroupService
from dalton.updater import SecurityGroupUpdater


def main(env, region, dry_run):
    basicConfig(
        level=INFO,
        format='%(asctime)s %(levelname)-3s %(name)s (%(funcName)s:%(lineno)d) %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    getLogger('boto').level = CRITICAL

    security_groups = YamlFileSecurityGroupsConfigLoader("config/%s/security_groups_%s.yaml" % (env, region)).load()
    updater = SecurityGroupUpdater(Ec2SecurityGroupService(yaml.load(open('config/aws.yaml', 'r').read())[env]))

    for name, security_group in security_groups.iteritems():
        created_new = updater.create_security_group_if_not_exists(name, security_group.description, region, dry_run)
        # Can't dry_run rules creation if the group doesn't actually exist yet
        if created_new and dry_run:
            continue
        updater.update_security_group_rules(name, security_group.rules, region,
                                            prune=security_group.prune, dry_run=dry_run)

    # Delete any groups that aren't listed in the ruleset config
    updater.delete_security_group_if(lambda group: group.name not in security_groups, region, vpc=None, dry_run=dry_run)


if __name__ == '__main__':
    options = docopt(__doc__, version='Dalton 0.1.0')
    main(options['<environment>'], options['<region>'], options['--dry-run'])
