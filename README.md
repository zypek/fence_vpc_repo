# fence_vpc_repo
AWS Security Group Modifier
This Python script modifies the Security Groups (SGs) attached to the network interfaces of an AWS EC2 instance. Specifically, it removes a specified Security Group from an interface, ensuring the interface remains properly configured.

Usage

Command

python3 script_name.py --instance-id <INSTANCE_ID> --sg <SECURITY_GROUP_ID>


Options
Option	Description	Required
--instance-id	The ID of the AWS EC2 instance.	Yes
--sg	The ID of the Security Group to be removed from the interface.	Yes

