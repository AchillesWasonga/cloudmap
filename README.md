# CloudMap

**CloudMap** is a multi-cloud misconfiguration scanner for AWS and Azure — designed to help developers, sysadmins and security engineers identify dangerous default settings and insecure configurations before attackers do.

> Think of it as a lightweight open-source alternative to ScoutSuite, Prowler, or AzSecPack — focused, fast, and developer-friendly.

---

## Features

**Multi-Cloud Support** – Scan AWS and Azure environments with a single CLI command  
**Security Group Analysis** – Detect open inbound rules (`0.0.0.0/0`) in AWS EC2 and Azure NSGs  
**S3 Bucket + Storage Checks** – Catch publicly accessible cloud storage  
**IAM Review** – Find overly permissive AWS IAM policies  
**Formatted Output** – View results in tables or JSON (for automation)  
**Modular Design** – Easy to extend, easy to integrate

---

## Installation

```bash
git clone https://github.com/AchillesWasonga/cloudmap.git
cd cloudmap
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> Python 3.8+ recommended

---

## Prerequisites

### 🟦 Azure
- Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- Login with:
  ```bash
  az login
  ```

### 🟥 AWS
- Create an AWS IAM user with read-only access
- Export credentials:
  ```bash
  export AWS_ACCESS_KEY_ID=your_access_key
  export AWS_SECRET_ACCESS_KEY=your_secret_key
  ```

---

## Configuration

Edit the `config/config.yaml` file to set regions or scanner-specific options for AWS and Azure.

---

## Usage

### Scan AWS
```bash
python -m cloudmap.cli --platform aws
```

### Scan Azure
```bash
python -m cloudmap.cli --platform azure
```

### Verbose (JSON) Output
```bash
python -m cloudmap.cli --platform aws --verbose
```

---

## Project Structure

```
cloudmap/
├── cloudmap/
│   ├── scanners/              # AWS and Azure scanners
│   ├── utils/                 # Output and misconfiguration helpers
│   ├── cli.py                 # Command-line interface
│   └── credentials.py         # Credential management
├── tests/                     # Unit tests for all major components
├── config/                    # Platform config files (YAML)
├── requirements.txt
└── README.md
```

---

## Contributing

Pull requests are welcome! If you'd like to:
- Add new cloud providers
- Expand misconfiguration rules
- Improve output visualization

Create an issue or fork and PR!

---

## 🛡️ License

MIT License. Free for personal and commercial use.

---

## 💬 Acknowledgments

Inspired by security tools like:
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [AzSecPack](https://github.com/azsec/azure-security-pack)

---

## 👨‍💻 Author

**Achilles** – [GitHub](https://github.com/AchillesWasonga) · [LinkedIn](https://www.linkedin.com/in/allan-wasonga-2b31252bb/)

```

---
