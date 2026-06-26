import os

from setuptools import setup, find_packages


def _read_requirements():
    """Read runtime deps from requirements.txt so it stays the single source of
    truth (skipping blank lines and comments)."""
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "requirements.txt")) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.lstrip().startswith("#")
        ]


setup(
    name="ramwingu",
    version="0.1.0",
    packages=find_packages(),
    install_requires=_read_requirements(),
    entry_points={
        "console_scripts": [
            "ramwingu=ramwingu.cli:main",
        ],
    },
    author="Allan Wasonga",
    description="Open-source multi-cloud misconfiguration scanner for AWS and Azure",
)
