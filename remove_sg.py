#!/usr/bin/env python3
import boto3
import argparse
import time
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

def modify_security_groups(ec2_client, network_interface_id, security_groups):
    """Modify the security groups attached to a specific network interface."""
    ec2_client.modify_network_interface_attribute(
        NetworkInterfaceId=network_interface_id,
        Groups=security_groups
    )

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

def main():
    parser = argparse.ArgumentParser(description="Modify Security Groups attached to an AWS instance.")
    parser.add_argument("--instance-id", required=True, help="The ID of the AWS instance.")
    parser.add_argument("--sg", required=True, help="The Security Group to remove.")
    args = parser.parse_args()

    instance_id = args.instance_id
    sg_to_remove = args.sg

    try:
        # Initialize EC2 client
        ec2_client = boto3.client('ec2')

        # Fetch instance details
        print(f"Querying details for instance: {instance_id}")
        instance_state, vpc_id, interfaces = get_instance_details(ec2_client, instance_id)

        print(f"Instance State: {instance_state}")
        print(f"Instance VPC ID: {vpc_id}")
        print("Network Interfaces and Attached Security Groups:")
        for interface in interfaces:
            print(f"  Interface: {interface['NetworkInterfaceId']}")
            print(f"  Attached SGs: {interface['SecurityGroups']}")

        # Create a backup tag before making any changes
        create_backup_tag(ec2_client, instance_id, interfaces)

        # Find the interface with the given SG
        target_interface = None
        for interface in interfaces:
            if sg_to_remove in interface['SecurityGroups']:
                target_interface = interface
                break

        if not target_interface:
            print(f"Security Group {sg_to_remove} not found on any interface of the instance.")
            sys.exit(1)

        # Remove the SG from the list and update the interface
        network_interface_id = target_interface['NetworkInterfaceId']
        updated_sgs = [sg for sg in target_interface['SecurityGroups'] if sg != sg_to_remove]

        if not updated_sgs:
            print(f"Cannot remove {sg_to_remove} as it would leave the interface with no security groups.")
            sys.exit(1)

        print(f"Updating interface {network_interface_id} with Security Groups: {updated_sgs}")
        modify_security_groups(ec2_client, network_interface_id, updated_sgs)

        # Wait for the changes to propagate
        time.sleep(5)

        # Confirm the change
        updated_interface = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[network_interface_id])['NetworkInterfaces'][0]
        print("Updated Security Groups:")
        print([sg['GroupId'] for sg in updated_interface['Groups']])

        print(f"Successfully removed {sg_to_remove} from interface {network_interface_id}.")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

