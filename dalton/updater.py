from logging import getLogger

log = getLogger(__name__)

class SecurityGroupUpdater(object):

    def __init__(self, security_group_service):
        self.security_group_service = security_group_service

    def update_security_group_rules(self, group_name, required_group_rules, region, vpc=None, prune=True, dry_run=False):
        # current_group_rules always have a security_group_id and only have security_group_name when in ec2 (not vpc)
        # required_group_rules could have either security_group_id or security_group_name for group rules
        # so we normalize both to have both a security_group_id and security_group_name
        current_group_rules = self.security_group_service.get_permissions(group_name, region, vpc)
        current_group_rules = self._normalize_security_group_rules(current_group_rules, region, vpc)
        required_group_rules = self._normalize_security_group_rules(required_group_rules, region, vpc)
        rules_to_add = required_group_rules - current_group_rules
        rules_to_remove = current_group_rules - required_group_rules
        location = "%s %s" % (region, vpc.id) if vpc else region
        if rules_to_add:
            log.info('Adding rules to group %s in %s: %s', group_name, location, self._rules_str(rules_to_add))
            self.security_group_service.authorize_ingress_rules(group_name, rules_to_add, region, vpc, dry_run)
        if rules_to_remove and prune:
            log.info('Removing rules from group %s in %s: %s', group_name, location, self._rules_str(rules_to_remove))
            self.security_group_service.revoke_ingress_rules(group_name, rules_to_remove, region, vpc, dry_run)

    def create_security_group_if_not_exists(self, group_name, description, region, vpc=None, dry_run=False):
        if not self.security_group_service.exists(group_name, region):
            log.info('Creating security group %s in %s' % (group_name, region))
            self.security_group_service.create(group_name, description, region, vpc=vpc, dry_run=dry_run)
            return True
        return False

    def delete_security_group_if(self, function, region, vpc=None, dry_run=False):
      for security_group in self.security_group_service.get_all(region, vpc=vpc):
        if function(security_group):
          log.info('Deleting security group %s in %s' % (security_group.name, region))
          self.security_group_service.delete(security_group.name, region, vpc=vpc, dry_run=dry_run)

    def _normalize_security_group_rules(self, required_group_rules, region, vpc=None):
        security_groups_by_id, security_groups_by_name = self._build_security_group_indices(region, vpc)
        return set(rule if self._rule_has_normalized_security_groups(rule)
                   else self._normalize_security_group_source(rule, security_groups_by_id, security_groups_by_name)
                   for rule in required_group_rules)

    def _build_security_group_indices(self, region, vpc=None):
        security_groups = self.security_group_service.get_all(region, vpc)
        security_groups_by_id = {group.id: group for group in security_groups}
        security_groups_by_name = {group.name: group for group in security_groups}
        return security_groups_by_id, security_groups_by_name

    @staticmethod
    def _normalize_security_group_source(rule, groups_by_id, groups_by_name):
        security_group = groups_by_id.get(rule.security_group_id) or groups_by_name.get(rule.security_group_name)
        if not security_group:
            raise Exception('Unknown security group for rule "%s"' % rule)
        rule.security_group_id = security_group.id
        rule.security_group_name = security_group.name
        return rule

    @staticmethod
    def _rule_has_normalized_security_groups(rule):
        no_security_group_set = not rule.security_group_name and not rule.security_group_id
        both_security_group_set = rule.security_group_id and rule.security_group_name
        return no_security_group_set or both_security_group_set

    @staticmethod
    def _rules_str(rules):
        return [str(rule) for rule in rules]
