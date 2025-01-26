#!/usr/libexec/platform-python -tt

import sys, re
import json
import atexit
import logging
import time
import boto3
import requests
from requests import HTTPError
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError

#sys.path.append("/usr/share/fence")
sys.path.append("/Users/robertbrodie/Documents/GitHub/fence-agents/lib")
from fencing import *
from fencing import (
    all_opt,
    check_input,
    process_input,
    run_delay,
    show_docs,
    fence_action,
    fail,
    fail_usage,
    atexit_handler,
    EC_STATUS,
    SyslogLibHandler,
)

try:
	import boto3
	from botocore.exceptions import ConnectionError, ClientError, EndpointConnectionError, NoRegionError
except ImportError:
	pass

# Logger configuration
logger = logging.getLogger()
logger.propagate = False
logger.setLevel(logging.INFO)
logger.addHandler(SyslogLibHandler())
logging.getLogger('botocore.vendored').propagate = False

status = {
		"running": "on",
		"stopped": "off",
		"pending": "unknown",
		"stopping": "unknown",
		"shutting-down": "unknown",
		"terminated": "unknown"
}

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
    all_opt["unfence-ignore-restore"] = {
        "getopt": "",
        "longopt": "unfence-ignore-restore",
        "help": "--unfence-ignore-restore              Do not restore security groups from tag when unfencing (off).",
        "shortdesc": "Remove all security groups except specified..",
        "required": "0",
        "order": 8,
    }

def get_power_status(conn, options):
	logger.debug("Starting status operation")
	try:
		instance = conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [options["--plug"]]}])
		state = list(instance)[0].state["Name"]
		logger.debug("Status operation for EC2 instance %s returned state: %s",options["--plug"],state.upper())
		try:
			return status[state]
		except KeyError as e:
			logger.error("Unknown status \"{}\" returned".format(state))
			return "unknown"
	except ClientError:
		fail_usage("Failed: Incorrect Access Key or Secret Key.")
	except EndpointConnectionError:
		fail_usage("Failed: Incorrect Region.")
	except IndexError:
		fail(EC_STATUS)
	except Exception as e:
		logger.error("Failed to get power status: %s", e)
		fail(EC_STATUS)

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
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]

        instance_state = instance["State"]["Name"]
        vpc_id = instance["VpcId"]
        network_interfaces = instance["NetworkInterfaces"]

        interfaces = []
        for interface in network_interfaces:
            try:
                interfaces.append(
                    {
                        "NetworkInterfaceId": interface["NetworkInterfaceId"],
                        "SecurityGroups": [sg["GroupId"] for sg in interface["Groups"]],
                    }
                )
            except KeyError as e:
                logger.error(f"Malformed interface data: {str(e)}")
                continue

        return instance_state, vpc_id, interfaces

    except ClientError as e:
        logger.error(f"AWS API error while retrieving instance details: {str(e)}")
        raise
    except IndexError as e:
        logger.error(f"Instance {instance_id} not found or no instances returned: {str(e)}")
        raise
    except KeyError as e:
        logger.error(f"Unexpected response format from AWS API: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while retrieving instance details: {str(e)}")
        raise

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
    try:
        sg_backup = {"NetworkInterfaces": interfaces}
        tag_value = json.dumps(sg_backup)

        tag_key = f"Original_SG_Backup_{instance_id}"
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[{"Key": tag_key, "Value": tag_value}],
        )
        logger.info(f"Backup tag '{tag_key}' created for instance {instance_id}.")
    except ClientError as e:
        logger.error(f"AWS API error while creating backup tag: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while creating backup tag: {str(e)}")
        raise


# Remove specified security groups
def remove_security_groups(ec2_client, instance_id, sg_list):
    """
    Removes all SGs in `sg_list` from each interface, if it doesn't leave zero SGs.
    If no changes are made to any interface, we exit with an error.
    
    Args:
        ec2_client: The boto3 EC2 client
        instance_id: The ID of the EC2 instance
        sg_list: List of security group IDs to remove
        
    Raises:
        ClientError: If AWS API calls fail
        Exception: For other unexpected errors
    """
    try:
        # Get instance details
        state, _, interfaces = get_instance_details(ec2_client, instance_id)
        
        try:
            # Create a backup tag before making changes
            create_backup_tag(ec2_client, instance_id, interfaces)
        except ClientError as e:
            logger.warning(f"Failed to create backup tag: {str(e)}")
            # Continue execution even if backup tag creation fails
        
        changed_any = False
        for interface in interfaces:
            try:
                original_sgs = interface["SecurityGroups"]
                # Exclude any SGs that are in sg_list
                updated_sgs = [sg for sg in original_sgs if sg not in sg_list]

                # If there's no change or we'd end up with zero SGs, skip
                if updated_sgs == original_sgs:
                    continue
                if not updated_sgs:
                    logger.info(
                        f"Skipping interface {interface['NetworkInterfaceId']}: "
                        f"removal of {sg_list} would leave 0 SGs."
                    )
                    continue

                logger.info(
                    f"Updating interface {interface['NetworkInterfaceId']} from {original_sgs} "
                    f"to {updated_sgs} (removing {sg_list})"
                )
                
                try:
                    ec2_client.modify_network_interface_attribute(
                        NetworkInterfaceId=interface["NetworkInterfaceId"],
                        Groups=updated_sgs
                    )
                    changed_any = True
                except ClientError as e:
                    logger.error(
                        f"Failed to modify security groups for interface "
                        f"{interface['NetworkInterfaceId']}: {str(e)}"
                    )
                    continue
                    
            except KeyError as e:
                logger.error(f"Malformed interface data: {str(e)}")
                continue

        # If we didn't remove anything, either the SGs weren't found or it left 0 SG
        if not changed_any:
            logger.error(
                f"Security Groups {sg_list} not removed from any interface. "
                f"Either not found, or removal left 0 SGs."
            )
            sys.exit(1)

        # Wait a bit for changes to propagate
        time.sleep(5)
        
    except ClientError as e:
        logger.error(f"AWS API error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise

def keep_only_security_groups(ec2_client, instance_id, sg_to_keep_list):
    """
    Removes all security groups from each network interface except for the specified ones.
    If none of the specified security groups are attached to an interface, that interface is skipped.
    
    Args:
        ec2_client: The boto3 EC2 client
        instance_id: The ID of the EC2 instance
        sg_to_keep_list: List containing the IDs of the security groups to keep
        
    Raises:
        ClientError: If AWS API calls fail
        Exception: For other unexpected errors
    """
    try:
        state, _, interfaces = get_instance_details(ec2_client, instance_id)

        try:
            # Create a backup tag before making changes
            create_backup_tag(ec2_client, instance_id, interfaces)
        except ClientError as e:
            logger.warning(f"Failed to create backup tag: {str(e)}")
            # Continue execution even if backup tag creation fails

        changed_any = False
        for interface in interfaces:
            try:
                original_sgs = interface["SecurityGroups"]
                
                # Check if any of the security groups to keep are attached
                sgs_to_keep = [sg for sg in original_sgs if sg in sg_to_keep_list]
                if not sgs_to_keep:
                    logger.info(
                        f"Skipping interface {interface['NetworkInterfaceId']}: "
                        f"none of the security groups {sg_to_keep_list} are attached."
                    )
                    continue

                # Set interface to only use the specified security groups
                updated_sgs = sgs_to_keep
                
                if updated_sgs == original_sgs:
                    continue

                logger.info(
                    f"Updating interface {interface['NetworkInterfaceId']} from {original_sgs} "
                    f"to {updated_sgs} (keeping only {sg_to_keep_list})"
                )
                
                try:
                    ec2_client.modify_network_interface_attribute(
                        NetworkInterfaceId=interface["NetworkInterfaceId"],
                        Groups=updated_sgs
                    )
                    changed_any = True
                except ClientError as e:
                    logger.error(
                        f"Failed to modify security groups for interface "
                        f"{interface['NetworkInterfaceId']}: {str(e)}"
                    )
                    continue
                    
            except KeyError as e:
                logger.error(f"Malformed interface data: {str(e)}")
                continue

        # If we didn't modify anything, the specified SGs weren't found on any interface
        if not changed_any:
            logger.error(
                f"Security Groups {sg_to_keep_list} not found on any interface. "
                f"No changes made."
            )
            sys.exit(1)

        # Wait a bit for changes to propagate
        time.sleep(5)
        
    except ClientError as e:
        logger.error(f"AWS API error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise

def restore_security_groups(ec2_client, instance_id):
    """
    Restores the original security groups from the backup tag to each network interface.
    
    Args:
        ec2_client: The boto3 EC2 client
        instance_id: The ID of the EC2 instance
        
    Raises:
        ClientError: If AWS API calls fail
        Exception: For other unexpected errors
    """
    try:
        # Get the backup tag
        response = ec2_client.describe_tags(
            Filters=[
                {"Name": "resource-id", "Values": [instance_id]},
                {"Name": "key", "Values": [f"Original_SG_Backup_{instance_id}"]}
            ]
        )
        
        if not response["Tags"]:
            logger.error(f"No backup tag found for instance {instance_id}")
            sys.exit(1)
            
        try:
            backup_data = json.loads(response["Tags"][0]["Value"])
            backup_interfaces = backup_data["NetworkInterfaces"]
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse backup data: {str(e)}")
            sys.exit(1)
            
        # Get current interfaces
        _, _, current_interfaces = get_instance_details(ec2_client, instance_id)
        
        # Create a map of interface IDs to their backup security groups
        backup_sg_map = {
            interface["NetworkInterfaceId"]: interface["SecurityGroups"]
            for interface in backup_interfaces
        }
        
        changed_any = False
        for interface in current_interfaces:
            try:
                interface_id = interface["NetworkInterfaceId"]
                if interface_id not in backup_sg_map:
                    logger.warning(
                        f"No backup data found for interface {interface_id}. Skipping."
                    )
                    continue
                    
                original_sgs = backup_sg_map[interface_id]
                current_sgs = interface["SecurityGroups"]
                
                if original_sgs == current_sgs:
                    logger.info(
                        f"Interface {interface_id} already has original security groups. Skipping."
                    )
                    continue
                
                logger.info(
                    f"Restoring interface {interface_id} from {current_sgs} "
                    f"to original security groups {original_sgs}"
                )
                
                try:
                    ec2_client.modify_network_interface_attribute(
                        NetworkInterfaceId=interface_id,
                        Groups=original_sgs
                    )
                    changed_any = True
                except ClientError as e:
                    logger.error(
                        f"Failed to restore security groups for interface "
                        f"{interface_id}: {str(e)}"
                    )
                    continue
                    
            except KeyError as e:
                logger.error(f"Malformed interface data: {str(e)}")
                continue
                
        if not changed_any:
            logger.error("No security groups were restored. All interfaces skipped.")
            sys.exit(1)
            
        # Wait for changes to propagate
        time.sleep(5)
        
        # Clean up the backup tag
        try:
            ec2_client.delete_tags(
                Resources=[instance_id],
                Tags=[{"Key": f"Original_SG_Backup_{instance_id}"}]
            )
            logger.info(f"Removed backup tag from instance {instance_id}")
        except ClientError as e:
            logger.warning(f"Failed to remove backup tag: {str(e)}")
            # Continue since the restore operation was successful
            
    except ClientError as e:
        logger.error(f"AWS API error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise

# Shutdown instance
def shutdown_instance(ec2_client, instance_id):
    """Shutdown the instance and confirm the state transition."""
    try:
        logger.info(f"Initiating shutdown for instance {instance_id}...")
        ec2_client.stop_instances(InstanceIds=[instance_id], Force=True)
 
        while True:
            try:
                state, _, _ = get_instance_details(ec2_client, instance_id)
                logger.info(f"Current instance state: {state}")
                if state == "stopping":
                    logger.info(
                        f"Instance {instance_id} is transitioning to 'stopping'. Proceeding without waiting further."
                    )
                    break
            except ClientError as e:
                logger.error(f"Failed to get instance state during shutdown: {str(e)}")
                fail_usage(f"AWS API error while checking instance state: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error while checking instance state: {str(e)}")
                fail_usage(f"Failed to check instance state: {str(e)}")

    except ClientError as e:
        logger.error(f"AWS API error during instance shutdown: {str(e)}")
        fail_usage(f"Failed to shutdown instance: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during instance shutdown: {str(e)}")
        fail_usage(f"Failed to shutdown instance due to unexpected error: {str(e)}")


# Perform the fencing action
def get_nodes_list(conn, options):
    """Get list of nodes and their status."""
    logger.debug("Starting monitor operation")
    result = {}
    try:
        if "--filter" in options:
            filter_key = options["--filter"].split("=")[0].strip()
            filter_value = options["--filter"].split("=")[1].strip()
            filter = [{"Name": filter_key, "Values": [filter_value]}]
            logging.debug("Filter: {}".format(filter))

        for instance in conn.instances.filter(Filters=filter if 'filter' in vars() else []):
            instance_name = ""
            for tag in instance.tags or []:
                if tag.get("Key") == "Name":
                    instance_name = tag["Value"]
            try:
                result[instance.id] = (instance_name, status[instance.state["Name"]])
            except KeyError as e:
                if options.get("--original-action") == "list-status":
                    logger.error("Unknown status \"{}\" returned for {} ({})".format(instance.state["Name"], instance.id, instance_name))
                result[instance.id] = (instance_name, "unknown")
    except Exception as e:
        logger.error("Failed to get node list: %s", e)
    return result

def set_power_status(conn, options):
    """Set power status of the instance."""
    ec2_client = conn.meta.client
    instance_id = options["--plug"]
    sg_to_remove = options.get("--sg", "").split(",") if options.get("--sg") else []

    # Perform self-check if skip-race not set
    if "--skip-race-check" not in options:
        self_instance_id = get_instance_id()
        if self_instance_id == instance_id:
            fail_usage("Self-fencing detected. Exiting.")

    # Verify the instance is running
    instance_state, _, _ = get_instance_details(ec2_client, instance_id)
    if instance_state != "running":
        fail_usage(f"Instance {instance_id} is not running. Exiting.")

    try:
        if options["--action"] == "off":
            if not "--unfence-ignore-restore" in options:
                restore_security_groups(ec2_client, instance_id)
            else:
                logger.info("Ignored Restoring security groups as --unfence-ignore-restore is set")
        elif options["--action"] == "on":
            if sg_to_remove:
                if "--invert-sg-removal" not in options:
                    remove_security_groups(ec2_client, instance_id, sg_to_remove)
                else:
                    keep_only_security_groups(ec2_client, instance_id, sg_to_remove)
    except Exception as e:
        logger.error("Failed to set power status: %s", e)
        fail(EC_STATUS)

def main():
    device_opt = [
        "port",
        "no_password",
        "region",
        "access_key",
        "secret_key",
        "sg",
        "plug",
        "skip_race_check",
        "invert-sg-removal",
        "unfence-ignore-restore",
        "filter",
        "boto3_debug"
    ]

    atexit.register(atexit_handler)
    define_new_opts()

    options = check_input(device_opt, process_input(device_opt))
    run_delay(options)

    docs = {
        "shortdesc": "Fence agent for AWS VPC",
        "longdesc": (
            "fence_aws_vpc is a Power Fencing agent for AWS VPC that works by "
            "manipulating security groups. It uses the boto3 library to connect to AWS.\n\n"
            "boto3 can be configured with AWS CLI or by creating ~/.aws/credentials.\n"
            "For instructions see: https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration"
        ),
        "vendorurl": "http://www.amazon.com"
    }
    show_docs(options, docs)

    # Configure logging
    if "--debug-file" in options:
        for handler in logger.handlers:
            if isinstance(handler, logging.FileHandler):
                logger.removeHandler(handler)
        lh = logging.FileHandler(options["--debug-file"])
        logger.addHandler(lh)
        lhf = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        lh.setFormatter(lhf)
        lh.setLevel(logging.DEBUG)

    # Configure boto3 logging
    if options.get("--boto3_debug", "").lower() not in ["1", "yes", "on", "true"]:
        boto3.set_stream_logger('boto3', logging.INFO)
        boto3.set_stream_logger('botocore', logging.CRITICAL)
        logging.getLogger('botocore').propagate = False
        logging.getLogger('boto3').propagate = False
    else:
        log_format = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        logging.getLogger('botocore').propagate = False
        logging.getLogger('boto3').propagate = False
        fdh = logging.FileHandler('/var/log/fence_aws_vpc_boto3.log')
        fdh.setFormatter(log_format)
        logging.getLogger('boto3').addHandler(fdh)
        logging.getLogger('botocore').addHandler(fdh)
        logging.debug("Boto debug level is %s and sending debug info to /var/log/fence_aws_vpc_boto3.log", 
                     options.get("--boto3_debug"))

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
        if not options.get("--action", "") in ["metadata", "manpage", "validate-all"]:
            fail_usage("Failed: Unable to connect to AWS: " + str(e))
        else:
            pass

    # Operate the fencing device using the fence library's fence_action
    result = fence_action(conn, options, set_power_status, get_power_status, get_nodes_list)
    sys.exit(result)


if __name__ == "__main__":
    main()
