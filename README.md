# fence_vpc_repo
AWS Security Group Modifier
This script modifies the Security Groups (SGs) attached to the network interfaces of an AWS EC2 instance. Specifically, it removes a specified Security Group from an interface, ensuring the interface remains correctly configured.

Usage
Command
bash
Copy
Edit
python3 script_name.py --instance-id <INSTANCE_ID> --sg <SECURITY_GROUP_ID>
Options
Option	Description	Required
--instance-id	The ID of the AWS EC2 instance.	Yes
--sg	The ID of the Security Group to be removed from the interface.	Yes
Example
Command
bash
Copy
Edit
python3 script_name.py --instance-id i-0123456789abcdef0 --sg sg-0123456789abcdef0
Expected Output
The script queries the instance to retrieve:
Current power state.
VPC ID.
Network interfaces and their attached Security Groups.
The script identifies the interface containing the specified Security Group.
If the Security Group is found:
It removes the Security Group from the list of attached SGs.
Updates the interface with the modified SG list.
If successful, it displays the updated Security Groups attached to the interface.
Pre-requisites
Python Environment:

Requires Python 3.x.
Install boto3 using:
bash
Copy
Edit
pip install boto3
AWS Credentials:

Ensure your AWS credentials are configured. You can use one of the following methods:
AWS CLI (aws configure).
Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).
IAM roles (if running on an AWS EC2 instance).
Permissions:

The IAM user or role must have the following permissions:
ec2:DescribeInstances
ec2:ModifyNetworkInterfaceAttribute
ec2:DescribeNetworkInterfaces
Workflow
Instance Query:

Retrieves instance details, including its current state, VPC, and attached SGs.
Identify Target Interface:

Finds the network interface where the specified Security Group is attached.
Validation:

Ensures the Security Group exists on the interface.
Prevents removal if it would leave the interface without any Security Groups.
Modification:

Removes the Security Group from the list.
Updates the interface with the revised list.
Confirmation:

Confirms the modification was successful by querying the updated list of SGs.
Error Handling
Security Group Not Found:

The script exits with an error if the specified SG is not attached to any interface.
No Remaining Security Groups:

The script prevents removing the SG if it would leave the interface without any SGs.
AWS API Errors:

The script captures and displays API errors for troubleshooting.
Notes
Force Removal:

The script ensures forced removal of the SG while maintaining interface integrity.
Sleep Time:

After modifications, the script waits for 5 seconds to allow AWS API changes to propagate.
