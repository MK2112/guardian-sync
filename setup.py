from setuptools import setup, find_packages

setup(
    name="guardian-sync",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "gnupg>=2.3.1",
        "watchdog>=2.1.9",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "pq": ["liboqs-python>=0.8.0"],
    },
    entry_points={
        "console_scripts": [
            "guardian-sync=src.main:main",
        ],
    },
    author="MK2112",
    author_email="mk2112@protonmail.com",
    description="A middleware for PGP encryption of cloud synced files",
    keywords="sync, pgp, encryption, security, cloud, guardian-sync",
    python_requires=">=3.10",
)
