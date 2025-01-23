#!/usr/libexec/platform-python -tt

import sys
import json
import boto3
import requests
import logging
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError

sys.path.append("/usr/share/fence")
from fencing import *
from fencing import fail, fail_usage, run_delay, EC_STATUS, SyslogLibHandler

# Logger configuration
logger = logging.getLogger()
logger.propagate = False
logger.setLevel(logging.INFO)
logger.addHandler(SyslogLibHandler())

# Security group states
status = {
    "running": "on",
    "stopped": "off",
    "pending": "unknown",
    "stopping": "unknown",
    "shutting-down": "unknown",
    "terminated": "unknown"
}

def define_new_opts():
    """Define the options for the fencing agent."""
    all_opt["region"] = {
        "getopt": "r:",
        "longopt": "region",
        "help": "-r, --region=[region]          AWS region, e.g. us-east-1",
        "shortdesc": "AWS Region.",
        "required": "0",
        "order": 1
    }
    all_opt["access_key"] = {
        "getopt": "a:",
        "longopt": "access-key",
        "help": "-a, --access-key=[key]         AWS access key.",
        "shortdesc": "AWS Access Key.",
        "required": "0",
        "order": 2
    }
    all_opt["secret_key"] = {
        "getopt": "s:",
        "longopt": "secret-key",
        "help": "-s, --secret-key=[key]         AWS secret key.",
        "shortdesc": "AWS Secret Key.",
        "required": "0",
        "order": 3
    }
    all_opt["sg"] = {
        "getopt": "g:",
        "longopt": "security-groups",
        "help": "-g, --sg=[sg1,sg2,...]         Comma-separated list of security groups to remove.",
        "shortdesc": "Security Groups to remove.",
        "required": "0",
        "order": 4
    }
    all_opt["plug"] = {
        "getopt": "n:",
        "longopt": "plug",
        "help": "-n, --plug=[id]                Instance ID or target identifier (mandatory).",
        "shortdesc": "Target instance identifier.",
        "required": "1",
        "order": 5
    }
    all_opt["skip_race_check"] = {
        "getopt": "",
        "longopt": "skip-race-check",
        "help": "--skip-race-check              Skip race condition check.",
        "shortdesc": "Skip race condition check.",
        "required": "0",
        "order": 6
    }

def get_instance_id(options):
    """Retrieve the instance ID of the current EC2 instance."""
    try:
        token = requests.put(
            'http://169.254.169.254/latest/api/token',
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        ).content.decode("UTF-8")
        instance_id = requests.get(
            'http://169.254.169.254/latest/meta-data/instance-id',
            headers={"X-aws-ec2-metadata-token": token}
        ).content.decode("UTF-8")
        return instance_id
    except HTTPError as http_err:
        logger.error('HTTP error occurred while accessing EC2 metadata: %s', http_err)
    except Exception as err:
        if "--skip-race-check" not in options:
            logger.error('Fatal error accessing EC2 metadata: %s', err)
        else:
            logger.debug('Error accessing EC2 metadata: %s', err)
    return None

def get_instance_details(ec2_client, instance_id):
    """Retrieve instance details including state, VPC, interfaces, and attached SGs."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]

        instance_state = instance['State']['Name']
        vpc_id = instance['VpcId']
        network_interfaces = instance['NetworkInterfaces']

        interfaces = [
            {
                "NetworkInterfaceId": iface['NetworkInterfaceId'],
                "SecurityGroups": [sg['GroupId'] for sg in iface['Groups']]
            }
            for iface in network_interfaces
        ]

        return instance_state, vpc_id, interfaces
    except Exception as e:
        fail_usage(f"Failed to fetch instance details: {str(e)}")

def create_backup_tag(ec2_client, instance_id, interfaces):
    """Create a tag on the instance to backup original security groups."""
    sg_backup = {"NetworkInterfaces": interfaces}
    tag_value = json.dumps(sg_backup)

    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "Original_SG_Backup", "Value": tag_value}
        ]
    )
    print(f"Backup tag 'Original_SG_Backup' created for instance {instance_id}.")

def remove_security_groups(ec2_client, instance_id, sg_to_remove):
    """Remove specified SGs from the instance's interfaces."""
    state, vpc_id, interfaces = get_instance_details(ec2_client, instance_id)

    # Create a backup tag before making changes
    create_backup_tag(ec2_client, instance_id, interfaces)

    for interface in interfaces:
        current_sgs = interface["SecurityGroups"]
        updated_sgs = [sg for sg in current_sgs if sg not in sg_to_remove]

        if not updated_sgs:
            print(f"Cannot remove SGs from interface {interface['NetworkInterfaceId']} as it would leave no SGs attached.")
            continue

        print(f"Updating interface {interface['NetworkInterfaceId']} with new SGs: {updated_sgs}")
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=interface["NetworkInterfaceId"],
            Groups=updated_sgs
        )

def shutdown_instance(ec2_client, instance_id):
    """Shutdown the instance."""
    print(f"Initiating shutdown for instance {instance_id}...")
    ec2_client.stop_instances(InstanceIds=[instance_id], Force=True)

def main():
    """Main entry point for the fencing agent."""
    device_opt = ["region", "access_key", "secret_key", "sg", "plug", "skip_race_check"]
    define_new_opts()

    # Parse options
    options = check_input(device_opt, process_input(device_opt))
    run_delay(options)

    region = options.get("--region")
    access_key = options.get("--access-key")
    secret_key = options.get("--secret-key")
    sg_to_remove = options.get("--sg").split(",") if options.get("--sg") else []
    instance_id = options.get("--plug")

    # Initialize EC2 connection
    try:
        ec2_client = boto3.client(
            "ec2",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    except Exception as e:
        fail_usage(f"Failed to connect to AWS: {str(e)}")

    # Fencing logic
    state, _, _ = get_instance_details(ec2_client, instance_id)
    if state != "running":
        fail_usage(f"Instance {instance_id} is not running.")

    remove_security_groups(ec2_client, instance_id, sg_to_remove)
    shutdown_instance(ec2_client, instance_id)

if __name__ == "__main__":
    main()

