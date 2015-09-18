#!/usr/bin/env python
"""
Dalton manages your security groups.

Usage:
  dalton [-d | --dry-run] <config-dir> <environment> <region>
  dalton -h | --help
  dalton --version

Options:
  -d --dry-run          Performs a "dry run" to show (but not perform) security group changes
  -v --version          Show version.
  -h --help             Show this screen.
"""

from logging import basicConfig, getLogger, CRITICAL, INFO

from docopt import docopt
from path import path
import yaml

from dalton.config import YamlFileSecurityGroupsConfigLoader
from dalton.ec2 import Ec2SecurityGroupService
from dalton.updater import SecurityGroupUpdater


def main(config_dir, env, region, dry_run):
    basicConfig(
        level=INFO,
        format='%(asctime)s %(levelname)-3s %(name)s (%(funcName)s:%(lineno)d) %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    getLogger('boto').level = CRITICAL

    security_groups = YamlFileSecurityGroupsConfigLoader("%s/%s/security_groups_%s.yaml" % (config_dir, env, region)).load()
    updater = SecurityGroupUpdater(Ec2SecurityGroupService(yaml.load(open('%s/aws.yaml' % config_dir, 'r').read())[env]))

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
    main(path(options['<config-dir>']), options['<environment>'], options['<region>'], options['--dry-run'])
