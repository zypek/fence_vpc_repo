#!/usr/bin/env python3

import boto3
import argparse
import sys
import time

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

def main():
    parser = argparse.ArgumentParser(description="Attach a Security Group to a specific AWS EC2 interface.")
    parser.add_argument("--instance-id", required=True, help="The ID of the AWS instance.")
    parser.add_argument("--sg", required=True, help="The Security Group to attach.")
    parser.add_argument("--interface-id", required=True, help="The network interface to modify.")
    args = parser.parse_args()

    instance_id = args.instance_id
    sg_to_attach = args.sg
    target_interface_id = args.interface_id

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

        # Find the target interface
        target_interface = next((iface for iface in interfaces if iface['NetworkInterfaceId'] == target_interface_id), None)

        if not target_interface:
            print(f"Interface {target_interface_id} not found for instance {instance_id}.")
            sys.exit(1)

        # Check if the SG is already attached
        current_sgs = target_interface['SecurityGroups']
        if sg_to_attach in current_sgs:
            print(f"Security Group {sg_to_attach} is already attached to interface {target_interface_id}.")
            sys.exit(0)

        # Add the SG to the list and update the interface
        updated_sgs = current_sgs + [sg_to_attach]
        print(f"Updating interface {target_interface_id} with Security Groups: {updated_sgs}")
        modify_security_groups(ec2_client, target_interface_id, updated_sgs)

        # Wait for the changes to propagate
        time.sleep(5)

        # Confirm the change
        updated_interface = ec2_client.describe_network_interfaces(NetworkInterfaceIds=[target_interface_id])['NetworkInterfaces'][0]
        print("Updated Security Groups:")
        print([sg['GroupId'] for sg in updated_interface['Groups']])

        print(f"Successfully attached {sg_to_attach} to interface {target_interface_id}.")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

