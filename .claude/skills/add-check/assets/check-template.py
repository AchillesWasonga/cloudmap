# Template: a misconfiguration check. Copy into the right scanner
# (ramwingu/scanners/aws.py or azure.py) and adapt. Delete this header.
#
# A check is a pure function over already-fetched resources that returns a
# list[str] of findings, or a single clean-status string when nothing is wrong.


def check_<thing>(resources):
    """
    One-line statement of what this flags and why it matters.

    :param resources: Already-fetched resources (list of dicts for AWS, SDK
        objects for Azure). Passed in so this is unit-testable with a fake.
    :return: List of human-readable issue strings.
    """
    issues = []
    for resource in resources:
        resource_id = resource.get("Id", "Unknown")  # AWS dict; for Azure use .name

        if _is_insecure(resource):
            issues.append(
                f"[HIGH] <Resource> {resource_id} <what is wrong>; "
                f"<how to fix it>."
            )

    if not issues:
        # Exact clean-status string — tests assert on this verbatim.
        issues.append("No <thing> issues found.")
    return issues


def _is_insecure(resource):
    """Scanner-internal helper (underscore-prefixed, stays in this file)."""
    return False
