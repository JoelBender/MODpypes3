#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re

from distutils.core import setup
from setuptools import find_packages

# load in the project metadata
init_py = open(os.path.join("modpypes3", "__init__.py")).read()
metadata = dict(re.findall("""__([a-z]+)__ = ["]([^"]+)["]""", init_py))

setup(
    name="modpypes3",
    version=metadata["version"],
    description="MODBUS Communications Library",
    long_description="MODBUS communications library",
    author=metadata["author"],
    author_email=metadata["email"],
    url="https://github.com/JoelBender/modpypes3",
    packages=find_packages(),
    package_data={"modpypes3": ["py.typed"]},
    include_package_data=True,
    install_requires=[],
    license="MIT",
    zip_safe=False,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
