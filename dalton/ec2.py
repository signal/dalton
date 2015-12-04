from logging import getLogger

from boto.exception import EC2ResponseError
import boto.ec2
import boto.vpc
from cachetools import ttl_cache

from dalton.config.models import Rule
from dalton.service import SecurityGroupService

log = getLogger(__name__)


class Ec2SecurityGroupService(SecurityGroupService):
    """
    Manages EC2 security groups.
    """

    def __init__(self, credentials=None, connection=None):
        self.credentials = credentials
        self.connection = connection

    def create(self, group_name, description, region, vpc_id=None, dry_run=False):
        try:
            return self._client(region, vpc_id).create_security_group(group_name, description, dry_run=dry_run)
        except EC2ResponseError, e:
            log.info(e.message)

    def exists(self, group_name, region, vpc=None):
        return self.get_security_group(group_name, region, vpc) is not None

    def delete(self, group_id, region, vpc_id=None, dry_run=False):
        try:
            self._client(region, vpc_id).delete_security_group(group_id=group_id, dry_run=dry_run)
        except EC2ResponseError, e:
            log.info(e.message)

    @ttl_cache()
    def get_all(self, region, vpc_id):
        security_groups = self._client(region, vpc_id).get_all_security_groups()
        return [security_group for security_group in security_groups
                if (not vpc_id and not security_group.vpc_id) or (vpc_id == security_group.vpc_id)]

    def get_security_group(self, group_name, region, vpc):
        matching = filter(lambda group: group.name == group_name, self.get_all(region, vpc))
        return matching[0] if matching else None

    def get_permissions(self, group_name, region, vpc_id=None):
        security_group = self.get_security_group(group_name, region, vpc_id)
        return self._from_ip_permissions(security_group.rules) if security_group else set()

    def authorize_ingress_rules(self, group_name, rules, region, vpc_id=None, dry_run=False):
        for rule in rules:
            try:
                self._client(region, vpc_id).authorize_security_group(dry_run=dry_run,
                                                                   **self._to_ip_permissions(rule, group_name, region, vpc_id))
            except EC2ResponseError, e:
                log.info(e.message)

    def revoke_ingress_rules(self, group_name, rules, region, vpc_id=None, dry_run=False):
        for rule in rules:
            try:
                self._client(region, vpc_id).revoke_security_group(dry_run=dry_run,
                                                                **self._to_ip_permissions(rule, group_name, region, vpc_id))
            except EC2ResponseError, e:
                log.info(e.message)

    def _client(self, region, vpc):
        return boto.vpc.connect_to_region(region, **self.credentials) \
            if vpc else boto.ec2.connect_to_region(region, **self.credentials)

    def _to_ip_permissions(self, rule, group_name, region, vpc=None):
        if rule.protocol == 'icmp' and rule.from_port == '0' and rule.to_port == '255':
            from_port, to_port = -1, -1
        elif rule.protocol == 'icmp' and rule.from_port == rule.to_port:
            from_port, to_port = rule.from_port, -1
        else:
            from_port, to_port = int(rule.from_port), int(rule.to_port)
        source = {'ip_protocol': rule.protocol, 'from_port': from_port, 'to_port': to_port}
        dest = {'group_id': self.get_security_group(group_name, region, vpc).id}
        if rule.security_group_name:
            #TODO: will break if "Type" for security rule is "All traffic"
            source['src_security_group_group_id'] = self.get_security_group(rule.security_group_name, region, vpc).id
        elif rule.security_group_id:
            source['src_security_group_group_id'] = rule.security_group_id
        else:
            source['cidr_ip'] = rule.address
        return dict(source.items() + dest.items())

    @classmethod
    def _from_ip_permissions(cls, rules):
        return set(cls._ec2_grant_to_dalton_rule(rule, grant) for rule in rules for grant in rule.grants)

    @classmethod
    def _ec2_grant_to_dalton_rule(cls, rule, grant):
        if rule.ip_protocol == 'icmp' and rule.from_port == '-1' and rule.to_port == '-1':
            from_port, to_port = 0, 255
        elif rule.ip_protocol == 'icmp' and rule.from_port != '-1' and rule.to_port == '-1':
            from_port, to_port = int(rule.from_port), int(rule.from_port)
        else:
              from_port, to_port = int(rule.from_port), int(rule.to_port)
        return Rule(protocol=rule.ip_protocol, security_group_id=grant.group_id, security_group_name=grant.name,
                    address=grant.cidr_ip, from_port=from_port, to_port=to_port)
