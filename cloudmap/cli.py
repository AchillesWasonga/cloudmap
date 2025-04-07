import click
import yaml
import os
from cloudmap import credentials, logger
from cloudmap.utils.output_formatter import format_output

log = logger.get_logger()

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

@click.command()
@click.option("--platform", type=click.Choice(["aws", "azure"]), required=True, help="Cloud platform to scan.")
def main(platform):
    log.info("Starting CloudMap scan for %s", platform)
    config = load_config()
    creds = credentials.get_credentials(platform)
    
    if platform == "aws":
        from cloudmap.scanners.aws import run_scan_with_aws_credentials
        findings = run_scan_with_aws_credentials(config.get("aws", {}), creds)
    elif platform == "azure":
        from cloudmap.scanners import azure
        findings = azure.run_scan_with_az_login(config.get("azure", {}), creds)
    else:
        click.echo("Unsupported platform.")
        return

    click.echo(format_output(findings))

if __name__ == "__main__":
    main()
