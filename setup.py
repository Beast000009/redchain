from setuptools import setup, find_packages

setup(
    name="redchain",
    version="2.0.0",
    description="RedChain — Autonomous AI Red Team Agent",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="RedChain Contributors",
    license="MIT",
    python_requires=">=3.11",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "langgraph",
        "langchain-core",
        "google-genai",
        "python-nmap",
        "dnspython",
        "python-whois",
        "shodan",
        "typer",
        "rich",
        "pydantic",
        "pydantic-settings",
        "jinja2",
        "weasyprint",
        "httpx",
        "beautifulsoup4",
        "ipinfo",
        "packaging",
    ],
    entry_points={
        "console_scripts": [
            "redchain=cli:app",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
