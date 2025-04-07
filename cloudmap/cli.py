import click
from cloudmap import credentials, logger
from cloudmap.utils.output_formatter import format_output

log = logger.get_logger()

def scan_multiple_accounts(platform, config, creds_list):
    all_findings = {}
    for creds in creds_list:
        if platform == "aws":
            from cloudmap.scanners import aws
            findings = aws.scan(config.get("aws", {}), creds)
            account_id = creds.get("aws_access_key_id")[-4:]  # Just as an identifier
            all_findings[account_id] = findings
        elif platform == "azure":
            from cloudmap.scanners import azure
            findings = azure.scan(config.get("azure", {}), creds)
            account_id = creds.get("client_id")[-4:]
            all_findings[account_id] = findings
    return all_findings

@click.command()
@click.option("--platform", type=click.Choice(["aws", "azure"]), required=True, help="Cloud platform to scan.")
@click.option("--batch", is_flag=True, help="Enable batch scanning using multiple credentials from a file.")
@click.option("--creds-file", type=click.Path(exists=True), help="Path to credentials file for batch scanning.")
def main(platform, batch, creds_file):
    log.info("Starting CloudMap scan for %s", platform)
    config = {}  # Load your configuration as needed
    if batch:
        # Load credentials from the provided file (JSON/YAML)
        import json
        with open(creds_file) as f:
            creds_list = json.load(f)
        findings = scan_multiple_accounts(platform, config, creds_list)
    else:
        creds = credentials.get_credentials(platform)
        if platform == "aws":
            from cloudmap.scanners import aws
            findings = aws.scan(config.get("aws", {}), creds)
        elif platform == "azure":
            from cloudmap.scanners import azure
            findings = azure.scan(config.get("azure", {}), creds)
    click.echo(format_output(findings))

if __name__ == "__main__":
    main()
