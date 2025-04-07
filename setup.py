from setuptools import setup, find_packages

setup(
    name="cloudmap",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "PyYAML",
        "prompt_toolkit",
        "boto3",
        "azure-identity",
        "azure-mgmt-resource",
    ],
    entry_points={
        "console_scripts": [
            "cloudmap=cloudmap.cli:main",
        ],
    },
    author="Allan Wasonga",
    description="A cloud misconfiguration scanner for AWS and Azure",
)
