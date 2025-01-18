from setuptools import setup, find_packages

with open("README.md", "r") as f:
    readme = f.read()

setup(
    name="smp25519",
    version="1.0.0",
    description="Secure Messaging Protocol 25519",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/979st/smp25519-python",
    packages=find_packages(exclude=("examples", "svg")),
    license="Unlicense",
    install_requires=[
        "cryptography>=44.0.0",
        "blake3>=1.0.2",
        "pycryptodomex>=3.21.0"
    ],
    keywords=["python", "sockets", "udp", "secure", "x25519", "blake3", "chacha20", "protocol", "messaging"]
)