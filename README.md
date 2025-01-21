# Project Title

EC2 Instance Power Manager

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## About

This script allows users to manage the power state of an AWS EC2 instance. It supports actions like starting, stopping, and rebooting instances using the AWS SDK for Python (boto3).

## Features

- Query the current power state of an EC2 instance.
- Start, stop, or reboot an EC2 instance based on user input.
- Customisable actions when transitioning an instance to the 'off' state.
- Error handling and waiters for ensuring state transitions are complete.

## Installation

1. Ensure Python 3 is installed on your system.
2. Install the required Python package:
   ```bash
   pip install boto3
   ```
3. Configure AWS credentials for boto3 by setting up your AWS CLI or using environment variables.

## Usage

Run the script with the required arguments:

```bash
./ec2_power_manager.py --instance-id <INSTANCE_ID> --state <on|off> [--off-action <stop|reboot>]
```

### Arguments

- `--instance-id`: The ID of the EC2 instance to manage.
- `--state`: Desired power state (`on` or `off`).
- `--off-action`: Optional. Action to take when transitioning to `off`. Options are `stop` (default) or `reboot`.

### Example

To stop an EC2 instance:

```bash
./ec2_power_manager.py --instance-id i-0abcd1234efgh5678 --state off --off-action stop
```

To start an EC2 instance:

```bash
./ec2_power_manager.py --instance-id i-0abcd1234efgh5678 --state on
```

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Name:** Your Name
- **Email:** your.email@example.com
- **GitHub:** [username](https://github.com/username)


