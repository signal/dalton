# Dalton - Manages Your Security Groups.

Runs the [Road House](https://github.com/awsroadhouse/roadhouse) Security Groups.
Keeps the Bad Guys out and the Good Guys in.

Dalton consists of two pieces
1. Library to parse ruleset configs and update your cloud config
2. Dalton runner which reads one ruleset config per logical env / AWS region and updates AWS.

But wait, there's more!
3. Analysis web app which checks all AWS instances and highlights those that don't have the correct groups.
   You'll need to update this for your Security Group Policy. Currently requires "default" for all instances,
   a group which matches the server type (i.e., the server name prefix before the first digit), and a couple
   special cases for Cassandra and graphite names.

## History

Dalton started as a fork of [Road House](https://github.com/awsroadhouse/roadhouse) to support
- EC2 Classic instead of VPCs
- Separation of ruleset configs from updating (to eventually support non-AWS)

The eventual goal is to merge this back into Roadhouse. First we need to reintroduce solid support
for VPCs, as Shift (who produced Roadhouse) is very VPC-centric. Also, until the library supports
the existing Roadhouse API, a pull request is unlikely to be merged.

## Install

You are using `virtualenv`, right? Good. Most likely, you'll want to install dalton within its own `virtualenv`.

First create a virtualenv for dalton:

    $ mkdir -p ~/dev/envs
    $ virtualenv ~/dev/envs/dalton

Now, install all dependencies in the virtualenv:

    $ . ~/dev/envs/dalton/bin/activate
    $ pip install -r requires.txt

Dalton should now have access to the all required libraries.

## Library Usage

Security Group Rulesets are loaded and parsed using the `YamlFileSecurityGroupsConfigLoader`. For example,
to load a particular ruleset config for each AWS region:

    loader = YamlFileSecurityGroupsConfigLoader("config/prod/security_groups_us-east-1.yaml")
    security_groups = loader.load()

Different clouds can be used by specifying the correct `SecurityGroupService`. For example, to connect to AWS for your
production environment ("prod"), use the `Ec2SecurityGroupService`:

    ec2service = Ec2SecurityGroupService(yaml.load(open('config/aws.yaml', 'r').read())["prod"])

*Note: currently only AWS/EC2 is supported.*

The `SecurityGroupUpdater` coordinates rules addition/removal so that the cloud config matches the desired config.
Simply call `update_security_group_rules` for each security group:

    updater = SecurityGroupUpdater(ec2service)
    for name, security_group in security_groups.iteritems():
        updater.update_security_group_rules(name, security_group.rules, region, prune=security_group.prune, dry_run=dry_run)

## Dalton Configuration

Dalton assumes that you group your servers into separate logical environments such as "prod", "stage", "dev", etc.
Within each environment, it allows you to run multiple "regions" (geographically isolated and redundant locations).

There are two pieces of configuration for using the Dalton runner.

1. AWS Credentials: located in `<config-dir>/aws.yaml`.
2. Security Group Rulesets: located in `<config-dir>` with one environment `<env>` per directory and one region `<region>` per file.

The AWS Credentials file format is as follows.

    <env>:
      aws_access_key_id: <access_key>
      aws_secret_access_key: <secret_key>

The Security Group Ruleset files have a name of the format `<env>/security_groups_<region>.yaml`.
The format is best understood by example.

    <security-group-name>:
      options:
        description: <description>
        prune: <true if you want Dalton to remove unknown rules from the group>

      rules:
        - tcp port 0-65535 mygroup1     # Security Group 'mygroup1' to All TCP
        - udp port 0-65535 mygroup1     # Security Group 'mygroup1' to All UDP
        - icmp port 0-255 mygroup1      # Security Group 'mygroup1' to All ICMP
        - tcp port 80, 443 0.0.0.0/0    # Anywhere to HTTP/HTTPS
        - tcp port 22 1.2.3.4/32        # bastion host to SSH

See the [Road House README](https://github.com/awsroadhouse/roadhouse) for additional
Security Group Ruleset configuration details and examples.

## Dalton Usage

You probably want to know the changes before you perform them. Pass the `--dry-run` (or `-d`) flags for dry-run mode.

    ./dalton.py --dry-run <config-dir> <env> <region>

Once you're happy with the changes to be made, run

    ./dalton.py <config-dir> <env> <region>

## Tests

Tests are located in test directories inside each package. For each file `foo.py` there *should* be
a corresponding `test/test_foo.py`. Tests may be run using the [nose test runner](https://nose.readthedocs.org/en/latest/).

    $ nosetests

## Next Steps

1. Add missing unit tests.
2. Add support for the existing roadhouse API.
3. Fork roadhouse, extract improved library into it, and send pull request.
4. Improve multi-cloud security group abstraction. (VPC currently exposed in SecurityGroupService interface.)

## License

Copyright 2015 Signal Digital, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

