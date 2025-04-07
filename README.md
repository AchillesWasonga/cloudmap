# CloudMap

CloudMap is a platform-agnostic command-line scanner that detects common misconfigurations in cloud environments for AWS and Azure. It checks for vulnerabilities such as overly permissive security group rules, public S3 bucket misconfigurations, insecure IAM policies on AWS, and overly permissive NSG rules and public storage account configurations on Azure.

---

## Prerequisites

- **Python 3.8+**
- **Pip**
- **AWS CLI** (for AWS credential checks)
- **Azure CLI** (for Azure authentication and subscription management)

---

## Setup

1. **Clone the Repository**

   ```bash
   git clone https://your-repo-url.git
   cd cloudmap
   ```

2. **Create and Activate a Virtual Environment**

   ```bash
   python3 -m venv env
   source env/bin/activate   # On Windows use: env\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Scanner

CloudMap supports both AWS and Azure. The tool prompts for credentials (or uses CLI-based authentication for Azure) and runs scans based on your chosen platform.

### AWS

1. **Run the AWS Scanner**

   ```bash
   python -m cloudmap.cli --platform aws
   ```

2. **Enter AWS Credentials**  
   The tool will prompt you for:
   - **AWS Access Key ID**
   - **AWS Secret Access Key**

   These credentials are used for the duration of the scan. (Note: AWS does not have a logout command; credentials persist only for the session.)

3. **Review Results**  
   The scanner outputs findings such as:
   - Security groups with open (0.0.0.0/0) inbound rules.
   - S3 bucket ACL misconfigurations.
   - Overly permissive IAM policies.

### Azure

1. **Log In to Azure**

   Ensure you are logged in via the Azure CLI. In your terminal, run:

   ```bash
   az login
   ```

   Follow the prompts in your web browser (or use `az login --use-device-code` if needed).

2. **Run the Azure Scanner**

   ```bash
   python -m cloudmap.cli --platform azure
   ```

3. **Enter Your Subscription ID (if required)**  
   The scanner uses `DefaultAzureCredential` to authenticate. It first attempts to obtain the subscription ID from configuration or the `AZURE_SUBSCRIPTION_ID` environment variable. If not set, you will be prompted to enter your Azure Subscription ID (which you can find under the **Subscriptions** section in the Azure Portal).

   The tool then sets the subscription using:
   
   ```bash
   az account set --subscription <subscription_id>
   ```

4. **Automatic Logout**  
   Once the scan completes, CloudMap automatically logs you out of Azure using:

   ```bash
   az logout
   ```

5. **Review Results**  
   The scanner outputs findings such as:
   - NSG rules with overly permissive inbound settings (e.g., SSH open to 0.0.0.0/0).
   - Public access issues on storage accounts.

---

## Troubleshooting

### AWS
- **Permission Errors:**  
  If you encounter errors such as `ec2:DescribeSecurityGroups` or `s3:GetBucketAcl` AccessDenied, ensure that your AWS credentials have the following permissions:
  - `ec2:DescribeSecurityGroups`
  - `s3:GetBucketAcl` and `s3:ListBuckets`
  - `iam:ListUsers` and `iam:ListAttachedUserPolicies`

### Azure
- **Subscription ID Issues:**  
  If the scanner reports that the provided subscription ID is invalid, verify you have the correct subscription ID from the Azure Portal.
- **Authentication:**  
  Ensure you have run `az login` successfully before running the scanner. The tool uses `DefaultAzureCredential` to simplify authentication.

---

## Summary

- **For AWS:**  
  Run the scanner with:
  ```bash
  python -m cloudmap.cli --platform aws
  ```
  Enter your AWS credentials when prompted. The scanner will use these to list security groups, S3 buckets, and IAM policies.

- **For Azure:**  
  First, run:
  ```bash
  az login
  ```
  Then, run the scanner with:
  ```bash
  python -m cloudmap.cli --platform azure
  ```
  Enter your Azure Subscription ID if prompted. The scanner will automatically log you out of Azure after scanning.

CloudMap helps you proactively identify misconfigurations in your cloud environments. Enjoy scanning, and feel free to extend the tool to suit your needs!
```

