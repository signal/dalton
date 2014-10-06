# Dalton - Manages Your Security Groups.

Runs the [Road House](https://github.com/awsroadhouse/roadhouse) Security Groups.
Keeps the Bad Guys out and the Good Guys in.

## Configuration

There are two pieces of configuration for using Dalton.

1. AWS Credentials: located in `./config/aws.yaml`.
2. Security Group Rules: located in `./config` with one environment `<env>` per directory.

See the [Road House README](https://github.com/awsroadhouse/roadhouse) for configuration file format and examples.

## Usage

Run it with

    ./dalton.py <env> <region>
