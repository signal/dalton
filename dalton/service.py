class SecurityGroupService(object):

    def create(self, group_name, description, location, dry_run=False):
        raise NotImplementedError()

    def exists(self, group_name, location):
        raise NotImplementedError()

    def delete(self, group_name, location, dry_run=False):
        raise NotImplementedError()

    def get_all(self, location):
        raise NotImplementedError()

    def get_permissions(self, group_name, location):
        raise NotImplementedError()

    def authorize_ingress_rules(self, group_name, rules, location, dry_run=False):
        raise NotImplementedError()

    def revoke_ingress_rules(self, group_name, rules, location, dry_run=False):
        raise NotImplementedError()
