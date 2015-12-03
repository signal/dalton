from dalton.config import YamlFileSecurityGroupsConfigLoader
from dalton.ec2 import Ec2SecurityGroupService
from dalton.updater import SecurityGroupUpdater

class SecurityGroupsConfig(object):
    """
    Preserves the original Roadhouse API:
        ec2 = boto.vpc.connect_to_region('us-west-2')
        vpc = ec2.get_all_vpcs()[0]

        config = SecurityGroupsConfig.load('roadhouse.yaml')
        config.configure(ec2)
        config.apply(vpc)
    """

    def __init__(self, security_groups):
      self.security_groups = security_groups

    @classmethod
    def load(cls, filename):
      security_groups = YamlFileSecurityGroupsConfigLoader(filename).load()
      return SecurityGroupsConfig(security_groups)

    def configure(self, ec2):
      self.region = ec2.region
      self.service = Ec2SecurityGroupService(connection=ec2)
      self.updater = SecurityGroupUpdater(self.service)

    def apply(self, vpc=None):
      rack = vpc if vpc else None
      existing_groups = {group.name: group for group in self.service.get_all(self.region, rack)}
      security_groups = self.replace_rule_security_group_names_with_ids(self.security_groups, existing_groups)
      security_groups = self.index_by_security_group_id(security_groups, existing_groups)
      for name, security_group in security_groups.iteritems():
        self.updater.update_security_group_rules(security_group, security_group.rules, self.region)

    @staticmethod
    def replace_rule_security_group_names_with_ids(security_groups, existing_groups):
      for _, security_group in security_groups.iteritems():
        for rule in security_group.rules:
            if rule.security_group_name:
                rule.security_group_id = existing_groups[rule.security_group_name].id
                rule.security_group_name = None
      return security_groups

    @staticmethod
    def index_by_security_group_id(security_groups, existing_groups):
      return {existing_groups[name].id:group for name, group in security_groups.iteritems()}
