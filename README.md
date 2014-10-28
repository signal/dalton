# Dalton - Manages Your Security Groups.

Runs the [Road House](https://github.com/awsroadhouse/roadhouse) Security Groups.
Keeps the Bad Guys out and the Good Guys in.

## Install

You are using `virtualenv`, right? Good. Most likely, you'll want to install dalton within its own `virtualenv`.

First create a virtualenv for dalton:

    $ mkdir -p ~/dev/envs
    $ virtualenv ~/dev/envs/dalton

Now, install all dependencies in the virtualenv:

    $ . ~/dev/envs/dalton/bin/activate
    $ pip install -r requires.txt

Dalton should now have access to the all required libraries.

## Configuration

There are two pieces of configuration for using Dalton.

1. AWS Credentials: located in `./config/aws.yaml`.
2. Security Group Rules: located in `./config` with one environment `<env>` per directory and one region `<region>` per file.

See the [Road House README](https://github.com/awsroadhouse/roadhouse) for configuration file format and examples.

## Usage

You probably want to know the changes before you perform them. Pass the `--dry-run` (or `-d`) flags for dry-run mode.

    ./dalton.py --dry-run <env> <region>

Once you're happy with the changes to be made, run

    ./dalton.py <env> <region>

## Tests

Tests are located in test directories inside each package. For each file `foo.py` there *should* be
a corresponding `test/test_foo.py`. Tests may be run using the [nose test runner](https://nose.readthedocs.org/en/latest/).

    $ nosetests

## Next Steps

1. Add missing unit tests.
2. Add support for the existing roadhouse API.
3. Fork roadhouse, extract improved library into it, and send pull request.
4. Improve multi-cloud security group abstraction. (VPC currently exposed in SecurityGroupService interface.)
