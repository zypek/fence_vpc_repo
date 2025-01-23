#!/usr/libexec/platform-python -tt

import boto3
import requests
import logging
import time
import sys, re, json
from requests.exceptions import HTTPError
from botocore.exceptions import ClientError, EndpointConnectionError, NoRegionError

sys.path.append("/usr/share/fence")
import atexit
from fencing import *
from fencing import fail, fail_usage, run_delay, EC_STATUS, SyslogLibHandler

import requests
from requests import HTTPError

try:
	import boto3
	from botocore.exceptions import ConnectionError, ClientError, EndpointConnectionError, NoRegionError
except ImportError:
	pass

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

def get_instance_id(options):
	try:
		token = requests.put('http://169.254.169.254/latest/api/token', headers={"X-aws-ec2-metadata-token-ttl-seconds" : "21600"}).content.decode("UTF-8")
		r = requests.get('http://169.254.169.254/latest/meta-data/instance-id', headers={"X-aws-ec2-metadata-token" : token}).content.decode("UTF-8")
		return r
	except HTTPError as http_err:
		logger.error('HTTP error occurred while trying to access EC2 metadata server: %s', http_err)
	except Exception as err:
		if "--skip-race-check" not in options:
			logger.error('A fatal error occurred while trying to access EC2 metadata server: %s', err)
		else:
			logger.debug('A fatal error occurred while trying to access EC2 metadata server: %s', err)
	return None

def get_nodes_list(conn, options):
	logger.debug("Starting monitor operation")
	result = {}
	try:
		if "--filter" in options:
			filter_key   = options["--filter"].split("=")[0].strip()
			filter_value = options["--filter"].split("=")[1].strip()
			filter = [{ "Name": filter_key, "Values": [filter_value] }]
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
	except ClientError:
		fail_usage("Failed: Incorrect Access Key or Secret Key.")
	except EndpointConnectionError:
		fail_usage("Failed: Incorrect Region.")
	except ConnectionError as e:
		fail_usage("Failed: Unable to connect to AWS: " + str(e))
	except Exception as e:
		logger.error("Failed to get node list: %s", e)
	logger.debug("Monitor operation OK: %s",result)
	return result

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

def modify_security_groups(ec2_client, network_interface_id, security_groups):
	"""Modify the security groups attached to a specific network interface."""
	try:
		ec2_client.modify_network_interface_attribute(
			NetworkInterfaceId=network_interface_id,
			Groups=security_groups
		)
	except Exception as e:
		logger.error("Failed to modify security groups: %s", e)
		fail(EC_STATUS)

def create_backup_tag(conn, ec2_client, instance_id, interfaces):
	"""Create a tag on the instance to backup original security groups."""
	try:
		# Verify instance exists using conn.instances.filter
		instance = list(conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [instance_id]}]))
		if not instance:
			logger.error("Instance %s not found", instance_id)
			fail(EC_STATUS)
			
		sg_backup = {"NetworkInterfaces": interfaces}
		tag_value = json.dumps(sg_backup)
		ec2_client.create_tags(
			Resources=[instance_id],
			Tags=[{"Key": "Original_SG_Backup", "Value": tag_value}]
		)
		logger.debug("Backup tag 'Original_SG_Backup' created for instance %s", instance_id)
	except Exception as e:
		logger.error("Failed to create backup tag: %s", e)
		fail(EC_STATUS)

def get_instance_details(conn, instance_id):
	"""Retrieve instance details including state, VPC, interfaces, and attached SGs."""
	try:
		instance = list(conn.instances.filter(Filters=[{"Name": "instance-id", "Values": [instance_id]}]))[0]
		
		instance_state = instance.state["Name"]
		vpc_id = instance.vpc_id
		
		interfaces = []
		for interface in instance.network_interfaces:
			interfaces.append({
				"NetworkInterfaceId": interface.id,
				"SecurityGroups": [sg['GroupId'] for sg in interface.groups]
			})
		
		return instance_state, vpc_id, interfaces
	except Exception as e:
		logger.error("Failed to get instance details: %s", e)
		fail(EC_STATUS)

def set_sg_fence(conn, options):
	my_instance = get_instance_id(options)
	try:
		if (options["--action"]=="off"):
			if "--skip-race-check" in options or get_self_power_status(conn,my_instance) == "ok":
				# Get EC2 client for lower-level API access
				ec2_client = boto3.client('ec2', region_name=options.get("--region"),
										aws_access_key_id=options.get("--access-key"),
										aws_secret_access_key=options.get("--secret-key"))
				
				# Get instance details using conn.filter
				instance_state, vpc_id, interfaces = get_instance_details(conn, options["--plug"])
				logger.debug("Instance %s state: %s, VPC: %s", options["--plug"], instance_state, vpc_id)
				
				# Create backup of current security groups
				create_backup_tag(conn, ec2_client, options["--plug"], interfaces)
				
				# Find interface with the security group to remove
				sg_to_remove = options["--sg"]
				target_interface = None
				for interface in interfaces:
					if sg_to_remove in interface['SecurityGroups']:
						target_interface = interface
						break
				
				if not target_interface:
					logger.error("Security Group %s not found on any interface of instance %s", sg_to_remove, options["--plug"])
					fail(EC_STATUS)
				
				# Remove the security group
				network_interface_id = target_interface['NetworkInterfaceId']
				updated_sgs = [sg for sg in target_interface['SecurityGroups'] if sg != sg_to_remove]
				
				if not updated_sgs:
					logger.error("Cannot remove SG %s as it would leave interface with no security groups", sg_to_remove)
					fail(EC_STATUS)
				
				logger.debug("Updating interface %s with Security Groups: %s", network_interface_id, updated_sgs)
				modify_security_groups(ec2_client, network_interface_id, updated_sgs)
				
				logger.debug("Successfully removed %s from interface %s", sg_to_remove, network_interface_id)
			else:
				logger.debug("Skipping fencing as instance is not in running status")
		elif (options["--action"]=="on"):
			logger.debug(" On action not curretly implemented for SG fencing")
	except Exception as e:
		logger.error("Failed to execute SG fence action %s on %s: %s", 
				options["--action"], options["--plug"], e)
		fail(EC_STATUS)

def define_new_opts():
	all_opt["region"] = {
		"getopt" : "r:",
		"longopt" : "region",
		"help" : "-r, --region=[region]          Region, e.g. us-east-1",
		"shortdesc" : "Region.",
		"required" : "0",
		"order" : 2
	}
	all_opt["access_key"] = {
		"getopt" : "a:",
		"longopt" : "access-key",
		"help" : "-a, --access-key=[key]         Access Key",
		"shortdesc" : "Access Key.",
		"required" : "0",
		"order" : 3
	}
	all_opt["secret_key"] = {
		"getopt" : "s:",
		"longopt" : "secret-key",
		"help" : "-s, --secret-key=[key]         Secret Key",
		"shortdesc" : "Secret Key.",
		"required" : "0",
		"order" : 4
	}
	all_opt["sg"] = {
		"getopt" : "g:",
		"longopt" : "sg",
		"help" : "-g, --sg=[sg-id]              Security Group ID to remove",
		"shortdesc" : "Security Group ID.",
		"required" : "1",
		"order" : 5
	}
	all_opt["filter"] = {
		"getopt" : ":",
		"longopt" : "filter",
		"help" : "--filter=[key=value]           Filter (e.g. vpc-id=[vpc-XXYYZZAA])",
		"shortdesc": "Filter for list-action",
		"required": "0",
		"order" : 6
	}
	all_opt["boto3_debug"] = {
		"getopt" : "b:",
		"longopt" : "boto3_debug",
		"help" : "-b, --boto3_debug=[option]     Boto3 and Botocore library debug logging",
		"shortdesc": "Boto Lib debug",
		"required": "0",
		"default": "False",
		"order": 7
	}
	all_opt["skip_race_check"] = {
		"getopt" : "",
		"longopt" : "skip-race-check",
		"help" : "--skip-race-check              Skip race condition check",
		"shortdesc": "Skip race condition check",
		"required": "0",
		"order": 8
	}

# Main agent method
def main():
	conn = None

	device_opt = ["port", "no_password", "region", "access_key", "secret_key", "sg", "filter", "boto3_debug", "skip_race_check"]

	atexit.register(atexit_handler)

	define_new_opts()

	all_opt["power_timeout"]["default"] = "60"

	options = check_input(device_opt, process_input(device_opt))

	docs = {}
	docs["shortdesc"] = "Fence agent for AWS (Amazon Web Services)"
	docs["longdesc"] = "fence_aws is a Power Fencing agent for AWS (Amazon Web\
Services). It uses the boto3 library to connect to AWS.\
\n.P\n\
boto3 can be configured with AWS CLI or by creating ~/.aws/credentials.\n\
For instructions see: https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration"
	docs["vendorurl"] = "http://www.amazon.com"
	show_docs(options, docs)

	run_delay(options)
	if "--debug-file" in options:
		for handler in logger.handlers:
			if isinstance(handler, logging.FileHandler):
				logger.removeHandler(handler)
		lh = logging.FileHandler(options["--debug-file"])
		logger.addHandler(lh)
		lhf = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		lh.setFormatter(lhf)
		lh.setLevel(logging.DEBUG)
	
	if options["--boto3_debug"].lower() not in ["1", "yes", "on", "true"]:
		boto3.set_stream_logger('boto3',logging.INFO)
		boto3.set_stream_logger('botocore',logging.CRITICAL)
		logging.getLogger('botocore').propagate = False
		logging.getLogger('boto3').propagate = False
	else:
		log_format = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
		logging.getLogger('botocore').propagate = False
		logging.getLogger('boto3').propagate = False
		fdh = logging.FileHandler('/var/log/fence_aws_boto3.log')
		fdh.setFormatter(log_format)
		logging.getLogger('boto3').addHandler(fdh)
		logging.getLogger('botocore').addHandler(fdh)
		logging.debug("Boto debug level is %s and sending debug info to /var/log/fence_aws_boto3.log", options["--boto3_debug"])

	region = options.get("--region")
	access_key = options.get("--access-key")
	secret_key = options.get("--secret-key")
	try:
		conn = boto3.resource('ec2', region_name=region,
				      aws_access_key_id=access_key,
				      aws_secret_access_key=secret_key)
	except Exception as e:
		if not options.get("--action", "") in ["metadata", "manpage", "validate-all"]:
			fail_usage("Failed: Unable to connect to AWS: " + str(e))
		else:
			pass

	# Operate the fencing device
	result = fence_action(conn, options, set_sg_fence, get_power_status, get_nodes_list)
	sys.exit(result)

if __name__ == "__main__":
	main()

