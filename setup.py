from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="sql-injection-scanner",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced SQL Injection Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/sql-injection-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sqlscanner=sqlscanner.cli:main",
        ],
    },
)