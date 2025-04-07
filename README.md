# CloudMap

CloudMap is a platform-agnostic CLI tool to scan AWS and Azure environments for common misconfigurations. It helps users detect insecure settings such as open ports, overly permissive policies, exposed data, and more.

## Features

- Scans for misconfigurations on AWS and Azure.
- Securely prompts for credentials without storing them.
- Modular design for easy extension.
- Enhanced CLI user interface.

## Usage

1. Install dependencies: `pip install -r requirements.txt`
2. Run the tool:
   ```bash
   python -m cloudmap.cli --platform aws
