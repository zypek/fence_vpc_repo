#!/usr/bin/env python3
import boto3
import argparse
import sys
import time

def get_instance_state(ec2_client, instance_id):
    """Retrieve the current power state of the EC2 instance."""
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    return instance['State']['Name']

def stop_instance(ec2_client, instance_id):
    """Stop the EC2 instance."""
    print(f"Stopping instance {instance_id}...")
    ec2_client.stop_instances(InstanceIds=[instance_id], Force=True)
    print("Waiting for instance to stop...")
    waiter = ec2_client.get_waiter('instance_stopped')
    waiter.wait(InstanceIds=[instance_id])
    print("Instance stopped successfully.")

def reboot_instance(ec2_client, instance_id):
    """Reboot the EC2 instance."""
    print(f"Rebooting instance {instance_id}...")
    ec2_client.reboot_instances(InstanceIds=[instance_id])
    print("Reboot command issued successfully.")

def start_instance(ec2_client, instance_id):
    """Start the EC2 instance."""
    print(f"Starting instance {instance_id}...")
    ec2_client.start_instances(InstanceIds=[instance_id])
    print("Waiting for instance to start...")
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])
    print("Instance started successfully.")

def main():
    parser = argparse.ArgumentParser(description="Manage EC2 instance power state.")
    parser.add_argument("--instance-id", required=True, help="The ID of the AWS instance.")
    parser.add_argument("--state", required=True, choices=["on", "off"], help="Desired power state: 'on' or 'off'.")
    parser.add_argument("--off-action", choices=["stop", "reboot"], default="stop",
                        help="Action to take when state is 'off': 'stop' or 'reboot'. Default is 'stop'.")
    args = parser.parse_args()

    instance_id = args.instance_id
    desired_state = args.state
    off_action = args.off_action

    try:
        # Initialize EC2 client
        ec2_client = boto3.client('ec2')

        # Get the current state of the instance
        print(f"Querying current state of instance {instance_id}...")
        current_state = get_instance_state(ec2_client, instance_id)
        print(f"Current state of instance {instance_id}: {current_state}")

        if current_state == "running" and desired_state == "on":
            print(f"Instance {instance_id} is already running. No action needed.")
        elif current_state == "running" and desired_state == "off":
            if off_action == "stop":
                stop_instance(ec2_client, instance_id)
            elif off_action == "reboot":
                reboot_instance(ec2_client, instance_id)
        elif current_state == "stopped" and desired_state == "off":
            print(f"Instance {instance_id} is already stopped. No action needed.")
        elif current_state == "stopped" and desired_state == "on":
            start_instance(ec2_client, instance_id)
        else:
            print(f"Instance {instance_id} is in an unexpected state: {current_state}. Exiting.")
            sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

