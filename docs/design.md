# CloudMap Design Document

## Overview

CloudMap is a modular CLI tool designed to scan AWS and Azure environments for misconfigurations that can lead to security breaches.

## Architecture

- **CLI Module (`cli.py`):** Entry point that loads configuration, credentials, and directs scanning based on the selected platform.
- **Credentials Module (`credentials.py`):** Securely handles runtime credential input without storing them.
- **Scanners:**  
  - `aws.py` implements AWS scanning using boto3.  
  - `azure.py` implements Azure scanning using the Azure SDK.
- **Utilities (`utils.py`):** Contains shared functions for misconfiguration checks and output formatting.
- **UI Module (`ui.py`):** Provides an interactive CLI/TUI interface using prompt_toolkit.

## Future Enhancements

- Extend misconfiguration checks in `utils.py`.
- Improve Azure scanning logic and integrate more robust API handling.
- Expand interactive UI features.
