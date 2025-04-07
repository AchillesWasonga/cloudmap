"""
Output Formatter

This module provides functionality to format scan results for easy reading.
"""

import json

def format_output(findings):
    """
    Formats the scan findings as a pretty-printed JSON string.
    
    :param findings: A dict containing the scan results.
    :return: A formatted JSON string.
    """
    return json.dumps(findings, indent=2)
