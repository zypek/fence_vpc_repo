# Project Title

AWS EC2 Management Tools

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## About

This project provides a set of Python scripts to manage AWS EC2 instances and their associated resources. It simplifies common tasks like managing instance power states, attaching or detaching security groups, and retrieving detailed instance information. The tools leverage the AWS SDK for Python (boto3) to interact with AWS resources.

## Features

- **Power State Management**: Start, stop, and reboot EC2 instances with ease.
- **Security Group Management**: Attach or detach security groups to/from network interfaces.
- **Instance Details**: Retrieve detailed information about instances, including state, VPC, network interfaces, and attached security groups.

## Installation

1. Ensure Python 3 is installed on your system.
2. Install the required Python package:
   ```bash
   pip3 install boto3
   ```
3. Configure AWS credentials for boto3 by setting up your AWS CLI or using environment variables.

## Usage

### Script 1: Manage EC2 Power State

**File**: `power_state.py`

Run the script to start, stop, or reboot an EC2 instance.

```bash
./power_state.py --instance-id <INSTANCE_ID> --state <on|off> [--off-action <stop|reboot>]
```

#### Arguments
- `--instance-id`: The ID of the EC2 instance to manage.
- `--state`: Desired power state (`on` or `off`).
- `--off-action`: Optional. Action to take when transitioning to `off`. Options are `stop` (default) or `reboot`.

#### Example

To stop an EC2 instance:
```bash
./power_state.py --instance-id i-0abcd1234efgh5678 --state off --off-action stop
```

### Script 2: Attach a Security Group

**File**: `attach_sg.py`

Run the script to attach a security group to a specific network interface of an EC2 instance.

```bash
./attach_sg.py --instance-id <INSTANCE_ID> --sg <SECURITY_GROUP_ID> --interface-id <NETWORK_INTERFACE_ID>
```

#### Arguments
- `--instance-id`: The ID of the EC2 instance.
- `--sg`: The ID of the security group to attach.
- `--interface-id`: The ID of the network interface to modify.

#### Example

To attach a security group to a specific interface:
```bash
./attach_sg.py --instance-id i-0abcd1234efgh5678 --sg sg-0abcd1234efgh5678 --interface-id eni-0abcd1234efgh5678
```

### Script 3: Remove a Security Group

**File**: `remove_sg.py`

Run the script to remove a security group from a network interface of an EC2 instance.

```bash
./remove_sg.py --instance-id <INSTANCE_ID> --sg <SECURITY_GROUP_ID>
```

#### Arguments
- `--instance-id`: The ID of the EC2 instance.
- `--sg`: The ID of the security group to remove.

#### Example

To remove a security group from an interface:
```bash
./remove_sg.py --instance-id i-0abcd1234efgh5678 --sg sg-0abcd1234efgh5678
```

### Common Notes

- Ensure that the target interface is correctly identified.
- Scripts include waiters to ensure changes are fully propagated.
- Handle errors gracefully with appropriate logs and exit codes.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Name**: Sebastian Baszczyj
- **Email**: sbaszczyj@gmail.com
- **GitHub**: [zypek](https://github.com/username)


