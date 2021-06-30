"""Module setup."""

import runpy
from setuptools import setup, find_packages
import importlib.util

PACKAGE_NAME = "acapy-mydata-did-protocol"
version_meta = runpy.run_path("./version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]


def parse_requirements(filename):
    """Load requirements from a pip requirements file."""
    lineiter = (line.strip() for line in open(filename))

    requirements_list = []

    for line in lineiter:
        if line and not line.startswith("#"):
            # check if already installed ?
            if line.startswith("aries-cloudagent") and (spec := importlib.util.find_spec("aries-cloudagent")) is None:
                continue

            requirements_list.append(line)

    return requirements_list


if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        install_requires=parse_requirements("requirements.txt"),
        python_requires=">=3.6.3",
        package_data={"mydata_did": ["requirements.txt"]},
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: OS Independent",
        ],
    )
