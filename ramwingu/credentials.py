import os
import getpass

def get_credentials(platform):
    """
    Prompt for credentials securely without storing them.
    For AWS, request access key and secret key.
    For Azure, return an empty dict to rely on DefaultAzureCredential.
    """
    creds = {}
    if platform == "aws":
        creds["aws_access_key_id"] = os.getenv("AWS_ACCESS_KEY_ID") or input("Enter AWS Access Key ID: ")
        creds["aws_secret_access_key"] = os.getenv("AWS_SECRET_ACCESS_KEY") or getpass.getpass("Enter AWS Secret Access Key: ")
    elif platform == "azure":
        # Since we're using DefaultAzureCredential for Azure, we don't need to prompt.
        # Make sure the user is logged in via az login and has AZURE_SUBSCRIPTION_ID set if needed.
        print("Using DefaultAzureCredential for Azure authentication. Make sure you have run 'az login'.")
        # Optionally, if you want to support manual entry of a subscription ID:
        if not os.getenv("AZURE_SUBSCRIPTION_ID"):
            sub_id = input("Enter your Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID env var): ").strip()
            os.environ["AZURE_SUBSCRIPTION_ID"] = sub_id
    else:
        raise ValueError("Unsupported platform for credentials.")
    return creds
