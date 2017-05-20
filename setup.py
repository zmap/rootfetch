# -*- coding: utf-8 -*-

from setuptools import setup

import os.path

base_dir = os.path.dirname(__file__)

about = {}
with open(os.path.join(base_dir, "rootfetch", "__about__.py")) as f:
    exec(f.read(), about)

setup(
    name = "rootfetch",
    description = "command line program for downloading various certificate root stores",
    version = about["__version__"],
    license = about["__license__"],
    author = about["__author__"],
    author_email = about["__email__"],
    keywords = "python ca root certificates",

    install_requires = [
        "beautifulsoup4",
        "semver>=2.7,<3",
        "sh>=1.12,<2",
    ],

    packages = [
        "rootfetch"
    ],

    entry_points={
        'console_scripts': [
            'rootfetch = rootfetch.__main__:main',
        ]
    }
)
