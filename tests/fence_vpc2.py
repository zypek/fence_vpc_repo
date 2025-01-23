#!/usr/libexec/platform-python -tt

import sys
import json
import boto3
import logging
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError

sys.path.append("/usr/share/fence")
from fencing import (
    all_opt,
    check_input,
    process_input,
    run_delay,
    show_docs,
    fence_action,
    fail_usage,
    SyslogLibHandler,
)

# Logger configuration
logger = logging.getLogger()
logger.propagate = False
logger.setLevel(logging.INFO)
logger.addHandler(SyslogLibHandler())

# Define fencing agent options
def define_new_opts():
    all_opt["region"] = {
        "getopt": "r:",
        "longopt": "region",
        "help": "-r, --region=[region]          AWS region (e.g., us-east-1)",
        "shortdesc": "AWS Region.",
        "required": "0",
        "order": 1,
    }
    all_opt["access_key"] = {
        "getopt": "a:",
        "longopt": "access-key",
        "help": "-a, --access-key=[key]         AWS access key.",
        "shortdesc": "AWS Access Key.",
        "required": "0",
        "order": 2,
    }
    all_opt["secret_key"] = {
        "getopt": "s:",
        "longopt": "secret-key",
        "help": "-s, --secret-key=[key]         AWS secret key.",
        "shortdesc": "AWS Secret Key.",
        "required": "0",
        "order": 3,
    }
    all_opt["sg"] = {
        "getopt": "g:",
        "longopt": "security-groups",
        "help": "-g, --sg=[sg1,sg2,...]         Comma-separated list of SGs to remove.",
        "shortdesc": "Security Groups to remove.",
        "required": "0",
        "order": 4,
    }
    all_opt["plug"] = {
        "getopt": "n:",
        "longopt": "plug",
        "help": "-n, --plug=[id]                Instance ID or target identifier (mandatory).",
        "shortdesc": "Target instance identifier.",
        "required": "1",
        "order": 5,
    }
    all_opt["skip_race_check"] = {
        "getopt": "",
        "longopt": "skip-race-check",
        "help": "--skip-race-check              Skip race condition check.",
        "shortdesc": "Skip race condition check.",
        "required": "0",
        "order": 6,
    }

# Retrieve instance details
def get_instance_details(ec2_client, instance_id):
    """Retrieve instance details including state, VPC, interfaces, and attached SGs."""
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response["Reservations"][0]["Instances"][0]

    instance_state = instance["State"]["Name"]
    vpc_id = instance["VpcId"]
    network_interfaces = instance["NetworkInterfaces"]

    interfaces = []
    for interface in network_interfaces:
        interfaces.append(
            {
                "NetworkInterfaceId": interface["NetworkInterfaceId"],
                "SecurityGroups": [sg["GroupId"] for sg in interface["Groups"]],
            }
        )

    return instance_state, vpc_id, interfaces

# Remove specified security groups
def remove_security_groups(ec2_client, instance_id, sg_to_remove):
    """Remove specified SGs from the instance's interfaces."""
    state, _, interfaces = get_instance_details(ec2_client, instance_id)
    for interface in interfaces:
        current_sgs = interface["SecurityGroups"]
        updated_sgs = [sg for sg in current_sgs if sg not in sg_to_remove]

        if not updated_sgs:
            logger.warning(
                f"Cannot remove all SGs from interface {interface['NetworkInterfaceId']}. At least one SG must remain."
            )
            continue

        logger.info(
            f"Updating interface {interface['NetworkInterfaceId']} with SGs: {updated_sgs}"
        )
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=interface["NetworkInterfaceId"], Groups=updated_sgs
        )

# Perform the fencing action
def fence_vpc_action(conn, options):
    """Main fencing logic."""
    ec2_client = conn.meta.client
    instance_id = options["--plug"]
    sg_to_remove = options.get("--sg", "").split(",") if options.get("--sg") else []

    instance_state, _, _ = get_instance_details(ec2_client, instance_id)
    if instance_state != "running":
        fail_usage(f"Instance {instance_id} is not running. Exiting.")

    remove_security_groups(ec2_client, instance_id, sg_to_remove)
    logger.info(f"Security groups removed from instance {instance_id}.")
    sys.exit(0)

# Main function
def main():
    device_opt = ["region", "access_key", "secret_key", "sg", "plug", "skip_race_check"]
    define_new_opts()

    # Parse and validate options
    options = check_input(device_opt, process_input(device_opt))
    run_delay(options)

    # Show help or metadata if requested
    docs = {
        "shortdesc": "Fence agent for AWS VPC.",
        "longdesc": "fence_vpc.py is a fencing agent for managing AWS instances "
                    "by manipulating security groups and instance states.",
        "vendorurl": "https://aws.amazon.com",
    }
    show_docs(options, docs)

    # Establish AWS connection
    region = options.get("--region")
    access_key = options.get("--access-key")
    secret_key = options.get("--secret-key")

    try:
        conn = boto3.resource(
            "ec2",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
    except Exception as e:
        fail_usage(f"Failed to connect to AWS: {str(e)}")

    # Perform the fencing action
    fence_vpc_action(conn, options)

if __name__ == "__main__":
    main()

