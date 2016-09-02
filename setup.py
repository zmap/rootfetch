from setuptools import setup
import rootfetch

setup(
    name = "rootfetch",
    description = "command line program for downloading various certificate root stores",
    version = rootfetch.__version__,
    license = rootfetch.__license__,
    author = rootfetch.__author__,
    author_email = rootfetch.__email__,
    keywords = "python json schema bigquery elastic search",

    install_requires = [
        "beautifulsoup4"
    ],

    packages = [
        "rootfetch"
    ],

    entry_points={
        'console_scripts': [
            'rootfetch = footfetch.__main__:main',
        ]
    }
)

