import click
import yaml
import os
from cloudmap import credentials, logger, scanners, ui

# Initialize logger
log = logger.get_logger()

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

@click.command()
@click.option("--platform", type=click.Choice(["aws", "azure"]), required=True, help="Cloud platform to scan.")
def main(platform):
    """
    CloudMap - Scan AWS and Azure for misconfigurations.
    """
    log.info("Starting CloudMap scan for %s", platform)
    
    config = load_config()

    # Prompt for credentials (or read from env variables)
    creds = credentials.get_credentials(platform)
    
    # If interactive UI is desired, launch it
    if os.getenv("USE_INTERACTIVE_UI", "false").lower() == "true":
        ui.launch_ui(platform, config, creds)
    else:
        # Run scanner based on platform
        if platform == "aws":
            findings = scanners.aws.scan(config.get("aws", {}), creds)
        elif platform == "azure":
            findings = scanners.azure.scan(config.get("azure", {}), creds)
        else:
            click.echo("Unsupported platform.")
            return

        # Format and print the results
        from cloudmap import utils
        output = utils.format_output(findings)
        click.echo(output)

if __name__ == "__main__":
    main()
# This script is the command-line interface for CloudMap, a cloud misconfiguration scanner.
# It uses the Click library to handle command-line arguments and options.
# The script initializes a logger, loads a configuration file, and prompts the user for credentials.
# Depending on the specified platform (AWS or Azure), it runs the appropriate scanner and outputs the findings.
# The script also supports an interactive UI mode, which can be enabled via an environment variable.
# The `load_config` function loads the configuration from a YAML file.
# The `main` function is the entry point for the command-line interface.
# It uses the Click library to define command-line options and arguments.
# The script is designed to be run from the command line, and it can be executed directly or imported as a module.
# The script uses the `click` library to create a command-line interface.
# It defines a command called `main` that takes a required option `--platform`.
# The script also includes a function to load configuration settings from a YAML file.
# It initializes a logger for logging messages and errors.
# The script uses the `os` module to handle file paths and environment variables.
# It imports various modules from the `cloudmap` package, including `credentials`, `logger`, `scanners`, and `ui`.
# The script is designed to be run from the command line, and it can be executed directly or imported as a module.