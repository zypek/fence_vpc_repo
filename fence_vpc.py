#!/usr/libexec/platform-python -tt

import sys
import json
import boto3
import requests
import logging
import time  # Ensure we can call time.sleep
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
    # IMPORTANT: Changed `longopt` to "sg" so that fence library uses options["--sg"].
    all_opt["sg"] = {
        "getopt": "g:",
        "longopt": "sg",
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
    all_opt["invert-sg-removal"] = {
        "getopt": "",
        "longopt": "invert-sg-removal",
        "help": "--invert-sg-removal              Remove all security groups except the specified one.",
        "shortdesc": "Remove all security groups except specified..",
        "required": "0",
        "order": 7,
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

# Check if we are the self-fencing node 

def get_self_power_status(conn, instance_id):
	try:
		instance = conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [instance_id]}])
		state = list(instance)[0].state["Name"]
		if state == "running":
			logger.debug("Captured my (%s) state and it %s - returning OK - Proceeding with fencing",instance_id,state.upper())
			return "ok"
		else:
			logger.debug("Captured my (%s) state it is %s - returning Alert - Unable to fence other nodes",instance_id,state.upper())
			return "alert"
	
	except ClientError:
		fail_usage("Failed: Incorrect Access Key or Secret Key.")
	except EndpointConnectionError:
		fail_usage("Failed: Incorrect Region.")
	except IndexError:
		return "fail"

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


# Remove specified security groups
def remove_security_groups(ec2_client, instance_id, sg_list):
    """
    Removes all SGs in `sg_list` from each interface, if it doesn't leave zero SGs.
    If no changes are made to any interface, we exit with an error.
    """
    state, _, interfaces = get_instance_details(ec2_client, instance_id)

    # Create a backup tag before making changes
    create_backup_tag(ec2_client, instance_id, interfaces)

    changed_any = False
    for interface in interfaces:
        original_sgs = interface["SecurityGroups"]
        # Exclude any SGs that are in sg_list
        updated_sgs = [sg for sg in original_sgs if sg not in sg_list]

        #print(sg_list)

        # If there's no change or we'd end up with zero SGs, skip
        if updated_sgs == original_sgs:
            continue
        if not updated_sgs:
            print(
                f"Skipping interface {interface['NetworkInterfaceId']}: "
                f"removal of {sg_list} would leave 0 SGs."
            )
            continue

        print(
            f"Updating interface {interface['NetworkInterfaceId']} from {original_sgs} "
            f"to {updated_sgs} (removing {sg_list})"
        )
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=interface["NetworkInterfaceId"],
            Groups=updated_sgs
        )
        changed_any = True

    # If we didn't remove anything, either the SGs weren't found or it left 0 SG
    if not changed_any:
        print(
            f"Security Groups {sg_list} not removed from any interface. "
            f"Either not found, or removal left 0 SGs."
        )
        sys.exit(1)

    # Wait a bit for changes to propagate
    time.sleep(5)

def keep_only_security_groups(ec2_client, instance_id, sg_to_keep_list):
    """
    Removes all security groups from each network interface except for the specified one.
    If the specified security group is not attached to an interface, that interface is skipped.
    
    Args:
        ec2_client: The boto3 EC2 client
        instance_id: The ID of the EC2 instance
        sg_to_keep_list: List containing the ID of the security group to keep
    """
    state, _, interfaces = get_instance_details(ec2_client, instance_id)

    # Create a backup tag before making changes
    create_backup_tag(ec2_client, instance_id, interfaces)

    changed_any = False
    for interface in interfaces:
        original_sgs = interface["SecurityGroups"]
        
        # Skip if the security group to keep isn't attached to this interface

        #str(list1).replace('[','').replace(']','')
        #if sg_to_keep not in original_sgs:
        # Check if any of the security groups to keep are attached
        sgs_to_keep = [sg for sg in original_sgs if sg in sg_to_keep_list]
        if not sgs_to_keep:
            print(
                f"Skipping interface {interface['NetworkInterfaceId']}: "
                f"none of the security groups {sg_to_keep_list} are attached."
            )
            continue

        # Set interface to only use the specified security groups
        updated_sgs = sgs_to_keep
        
        if updated_sgs == original_sgs:
            continue

        print(
            f"Updating interface {interface['NetworkInterfaceId']} from {original_sgs} "
            f"to {updated_sgs} (keeping only {sg_to_keep_list})"
        )
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=interface["NetworkInterfaceId"],
            Groups=updated_sgs
        )
        changed_any = True

    # If we didn't modify anything, the specified SG wasn't found on any interface
    if not changed_any:
        print(
            f"Security Groups {sg_to_keep_list} not found on any interface. "
            f"No changes made."
        )
        sys.exit(1)

    # Wait a bit for changes to propagate
    time.sleep(5)



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
    # Now that longopt = "sg", the fence library populates options["--sg"].
    sg_to_remove = options.get("--sg", "").split(",") if options.get("--sg") else []

    # Perform self-check if skip-race not set
    #if "--skip-race-check" in options or get_self_power_status(conn,my_instance) == "ok":
    
    if "--skip-race-check" not in options:
        self_instance_id = get_instance_id()
        if self_instance_id == instance_id:
            fail_usage("Self-fencing detected. Exiting.")

    # Verify the instance is running
    instance_state, _, _ = get_instance_details(ec2_client, instance_id)
    if instance_state != "running":
        fail_usage(f"Instance {instance_id} is not running. Exiting.")

    # Remove security groups (if provided) and shutdown the instance
    if sg_to_remove:
        if "--invert-sg-removal" not in options:
            remove_security_groups(ec2_client, instance_id, sg_to_remove)
        else:
            keep_only_security_groups(ec2_client, instance_id, sg_to_remove)

        #shutdown_instance(ec2_client, instance_id)


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
        "invert-sg-removal"
    ]


    define_new_opts()

    # Parse and validate options
    print("Defined options:", all_opt)

    options = check_input(device_opt, process_input(device_opt))
    print("Got Here")
    run_delay(options)

    # Show help or metadata if requested
    docs = {
        "shortdesc": "Fence agent for AWS VPC.",
        "longdesc": (
            "fence_vpc.py is a fencing agent for managing AWS instances "
            "by manipulating security groups and instance states."
        ),
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
