from setuptools import setup
import zschema

setup(
    name = "rootfetch",
    description = "command line program for downloading various certificate root stores",
    version = zschema.__version__,
    license = zschema.__license__,
    author = zschema.__author__,
    author_email = zschema.__email__,
    keywords = "python json schema bigquery elastic search",

    install_requires = [
        "beautifulsoup4"
    ],

    packages = [
        "rootfetch"
    ],

    entry_points={
        'console_scripts': [
            'zschema = footfetch.__main__:main',
        ]
    }
)

