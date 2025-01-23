#!/usr/libexec/platform-python -tt

import sys
import json
import boto3
import requests
import logging
import time
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError

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

# Retrieve instance ID for self-check
def get_instance_id():
    """Retrieve the instance ID of the current EC2 instance."""
    try:
        token = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        ).content.decode("UTF-8")
        instance_id = requests.get(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        ).content.decode("UTF-8")
        return instance_id
    except Exception as err:
        logger.error("Failed to retrieve instance ID for self-check: %s", err)
        return None

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

# Create a backup tag
def create_backup_tag(ec2_client, instance_id, interfaces):
    """Create a tag on the instance to backup original security groups."""
    sg_backup = {"NetworkInterfaces": interfaces}
    tag_value = json.dumps(sg_backup)

    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[{"Key": "Original_SG_Backup", "Value": tag_value}],
    )
    logger.info(f"Backup tag 'Original_SG_Backup' created for instance {instance_id}.")

# Modify security groups
def modify_security_groups(ec2_client, network_interface_id, security_groups):
    """Modify the security groups attached to a specific network interface."""
    ec2_client.modify_network_interface_attribute(
        NetworkInterfaceId=network_interface_id, Groups=security_groups
    )

# Remove specified security groups
def remove_security_groups(ec2_client, instance_id, sg_to_remove):
    """Remove specified SGs from the instance's interfaces."""
    _, _, interfaces = get_instance_details(ec2_client, instance_id)

    # Create a backup tag before making changes
    create_backup_tag(ec2_client, instance_id, interfaces)

    for sg in sg_to_remove:
        # Iterate over each interface to remove the SG
        target_interface = None
        for interface in interfaces:
            if sg in interface["SecurityGroups"]:
                target_interface = interface
                break

        if not target_interface:
            logger.warning(
                f"Security Group {sg} not found on any interface of the instance."
            )
            continue

        network_interface_id = target_interface["NetworkInterfaceId"]
        updated_sgs = [
            sg_id for sg_id in target_interface["SecurityGroups"] if sg_id != sg
        ]

        if not updated_sgs:
            logger.error(
                f"Cannot remove {sg} as it would leave interface {network_interface_id} with no security groups."
            )
            continue

        # Modify the network interface's security groups
        logger.info(
            f"Updating interface {network_interface_id} with Security Groups: {updated_sgs}"
        )
        try:
            modify_security_groups(ec2_client, network_interface_id, updated_sgs)
        except Exception as e:
            logger.error(
                f"Failed to update interface {network_interface_id}: {str(e)}"
            )
            continue

        logger.info(f"Successfully removed {sg} from interface {network_interface_id}.")
        time.sleep(5)  # Allow changes to propagate

# Shutdown instance
def shutdown_instance(ec2_client, instance_id):
    """Shutdown the instance and confirm the state transition."""
    logger.info(f"Initiating shutdown for instance {instance_id}...")
    ec2_client.stop_instances(InstanceIds=[instance_id], Force=True)

    while True:
        state, _, _ = get_instance_details(ec2_client, instance_id)
        logger.info(f"Current instance state: {state}")
        if state == "stopping":
            logger.info(
                f"Instance {instance_id} is transitioning to 'stopping'. Proceeding without waiting further."
            )
            break

# Perform the fencing action
def fence_vpc_action(conn, options):
    """Main fencing logic."""
    ec2_client = conn.meta.client
    instance_id = options["--plug"]
    sg_to_remove = options.get("--sg", "").split(",") if options.get("--sg") else []

    logger.info(f"Starting fencing action for instance {instance_id}.")

    # Perform self-check
    self_instance_id = get_instance_id()
    if self_instance_id == instance_id:
        fail_usage("Self-fencing detected. Exiting.")

    # Verify the instance is running
    instance_state, _, _ = get_instance_details(ec2_client, instance_id)
    if instance_state != "running":
        fail_usage(f"Instance {instance_id} is not running. Exiting.")

    # Remove security groups
    if sg_to_remove:
        logger.info(f"Removing security groups: {sg_to_remove} from instance {instance_id}.")
        remove_security_groups(ec2_client, instance_id, sg_to_remove)
    else:
        logger.warning("No security groups specified for removal.")

    # Shutdown the instance
    shutdown_instance(ec2_client, instance_id)

# Main function
def main():
    device_opt = [
        "region",
        "no_password",
        "access_key",
        "secret_key",
        "sg",
        "plug",
        "skip_race_check",
    ]
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

