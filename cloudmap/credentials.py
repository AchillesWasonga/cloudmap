import os
import getpass

def get_credentials(platform):
    """
    Prompt for credentials securely without storing them.
    For AWS, request access key and secret key.
    For Azure, request tenant, client_id, client_secret (or use device code flow).
    """
    creds = {}
    if platform == "aws":
        creds["aws_access_key_id"] = os.getenv("AWS_ACCESS_KEY_ID") or input("Enter AWS Access Key ID: ")
        creds["aws_secret_access_key"] = os.getenv("AWS_SECRET_ACCESS_KEY") or getpass.getpass("Enter AWS Secret Access Key: ")
    elif platform == "azure":
        creds["tenant_id"] = os.getenv("AZURE_TENANT_ID") or input("Enter Azure Tenant ID: ")
        creds["client_id"] = os.getenv("AZURE_CLIENT_ID") or input("Enter Azure Client ID: ")
        creds["client_secret"] = os.getenv("AZURE_CLIENT_SECRET") or getpass.getpass("Enter Azure Client Secret: ")
    else:
        raise ValueError("Unsupported platform for credentials.")
    return creds

