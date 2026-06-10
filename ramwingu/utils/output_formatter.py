# cloudmap/utils/output_formatter.py

import json
from rich.console import Console
from rich.table import Table
from io import StringIO

def format_output(findings):
    """
    Returns the full scan results as a pretty-printed JSON string.
    """
    return json.dumps(findings, indent=2)

def format_table(findings):
    """
    Creates a friendly, tabular summary of the scan results.
    
    :param findings: A dictionary containing scan results for various categories.
    :return: A string representation of the table.
    """
    # Create a table with two columns: Category and Issue
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim", width=20)
    table.add_column("Issue", style="bold")

    # Loop through each category in the findings and add rows for each issue
    for category, issues in findings.items():
        if isinstance(issues, list):
            for issue in issues:
                table.add_row(category, issue)
        else:
            table.add_row(category, str(issues))

    # Use a Console to capture the table output as a string
    console = Console(record=True)
    console.print(table)
    return console.export_text()
