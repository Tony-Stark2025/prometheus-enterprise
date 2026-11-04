from setuptools import setup, find_packages

setup(
    name="prometheus",
    version="2.5.0",
    description="Autonomous API Penetration Testing, Continuous Immunology & Contextual SWE Repair Platform",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "google-genai>=1.0.0",
        "google-cloud-aiplatform>=1.133.0",
        "fastapi>=0.115.6",
        "pydantic>=2.10.3",
        "pydantic-settings>=2.6.1",
        "aiosqlite>=0.20.0",
        "httpx>=0.28.1",
    ],
    entry_points={
        "console_scripts": [
            "prometheus-scan=prometheus.cli_scan:main",
        ],
    },
)

