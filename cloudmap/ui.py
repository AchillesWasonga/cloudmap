from prompt_toolkit import prompt

def launch_ui(platform, config, creds):
    """
    Launch an interactive UI for scanning.
    This example simply prompts the user before running the scan.
    """
    print(f"Launching interactive UI for {platform} scan...")
    user_input = prompt("Press Enter to start scanning or type 'exit' to cancel: ")
    if user_input.lower() == "exit":
        print("Scan cancelled.")
        return
    
    # Import and run the scanner for the platform
    if platform == "aws":
        from cloudmap.scanners import aws
        findings = aws.scan(config.get("aws", {}), creds)
    elif platform == "azure":
        from cloudmap.scanners import azure
        findings = azure.scan(config.get("azure", {}), creds)
    else:
        print("Unsupported platform.")
        return

    from cloudmap.utils import format_output
    print("Scan results:")
    print(format_output(findings))
