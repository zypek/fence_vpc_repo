#!/usr/bin/env python3

import boto3
import argparse
import sys
import json

def get_instance_details(ec2_client, instance_id):
    """Retrieve instance details including state, VPC, interfaces, and attached SGs."""
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]

    instance_state = instance['State']['Name']
    vpc_id = instance['VpcId']
    network_interfaces = instance['NetworkInterfaces']

    interfaces = []
    for interface in network_interfaces:
        interfaces.append({
            "NetworkInterfaceId": interface['NetworkInterfaceId'],
            "SecurityGroups": [sg['GroupId'] for sg in interface['Groups']]
        })

    return instance_state, vpc_id, interfaces

def get_instance_tag(ec2_client, instance_id, tag_key):
    """Retrieve a specific tag from the instance."""
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    tags = response['Reservations'][0]['Instances'][0].get('Tags', [])
    for tag in tags:
        if tag['Key'] == tag_key:
            return tag['Value']
    return None

def modify_security_groups(ec2_client, network_interface_id, security_groups):
    """Modify the security groups attached to a specific network interface."""
    ec2_client.modify_network_interface_attribute(
        NetworkInterfaceId=network_interface_id,
        Groups=security_groups
    )

def remove_instance_tag(ec2_client, instance_id, tag_key):
    """Remove a specific tag from the instance."""
    ec2_client.delete_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": tag_key}
        ]
    )
    print(f"Tag '{tag_key}' successfully removed from instance {instance_id}.")

def main():
    parser = argparse.ArgumentParser(description="Update Security Groups on AWS EC2 interfaces based on tags.")
    parser.add_argument("--instance-id", required=True, help="The ID of the AWS instance.")
    args = parser.parse_args()

    instance_id = args.instance_id
    tag_key = "Original_SG_Backup"

    try:
        # Initialize EC2 client
        ec2_client = boto3.client('ec2')

        # Fetch the tag
        print(f"Checking for tag '{tag_key}' on instance {instance_id}...")
        tag_value = get_instance_tag(ec2_client, instance_id, tag_key)

        if not tag_value:
            print(f"No tag '{tag_key}' found on instance {instance_id}. Exiting.")
            sys.exit(0)

        # Parse the tag value
        tag_data = json.loads(tag_value)
        interfaces_from_tag = tag_data.get("NetworkInterfaces", [])

        if not interfaces_from_tag:
            print(f"Tag '{tag_key}' exists but contains no interfaces or SGs. Exiting.")
            sys.exit(1)

        # Fetch current instance details
        print(f"Fetching current details for instance {instance_id}...")
        instance_state, vpc_id, current_interfaces = get_instance_details(ec2_client, instance_id)

        all_sgs_updated = True  # Flag to track if all updates are successful

        for interface_from_tag in interfaces_from_tag:
            tag_interface_id = interface_from_tag["NetworkInterfaceId"]
            tag_sgs = set(interface_from_tag["SecurityGroups"])

            # Find the matching current interface
            current_interface = next(
                (iface for iface in current_interfaces if iface["NetworkInterfaceId"] == tag_interface_id), None
            )

            if not current_interface:
                print(f"Interface {tag_interface_id} not found in current instance configuration. Skipping.")
                all_sgs_updated = False
                continue

            current_sgs = set(current_interface["SecurityGroups"])

            if current_sgs == tag_sgs:
                print(f"Interface {tag_interface_id} already has the correct SGs. No action needed.")
                continue

            # Update SGs by expanding with SGs from the tag
            updated_sgs = list(current_sgs.union(tag_sgs))
            print(f"Updating interface {tag_interface_id} with new SGs: {updated_sgs}")
            modify_security_groups(ec2_client, tag_interface_id, updated_sgs)

            # Fetch updated SGs to confirm
            updated_interface = ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=[tag_interface_id]
            )['NetworkInterfaces'][0]
            updated_sgs_confirmed = [sg['GroupId'] for sg in updated_interface['Groups']]

            # Compare the confirmed SGs with the expected updated SGs
            if set(updated_sgs_confirmed) != set(updated_sgs):
                print(f"Failed to confirm updated SGs for interface {tag_interface_id}. Expected: {updated_sgs}, Found: {updated_sgs_confirmed}")
                all_sgs_updated = False
            else:
                print(f"Successfully confirmed updated SGs for interface {tag_interface_id}: {updated_sgs_confirmed}")

        if all_sgs_updated:
            print(f"All interfaces have been successfully updated. Removing tag '{tag_key}'...")
            remove_instance_tag(ec2_client, instance_id, tag_key)
        else:
            print(f"Some interfaces were not updated successfully. Retaining tag '{tag_key}' for debugging.")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

