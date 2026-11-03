from setuptools import setup, find_packages

setup(
    name="prometheus",
    version="1.1.0",
    description="Autonomous API Penetration Testing & Runtime Capability Hypervisor",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "google-genai>=0.1.1",
        "google-cloud-aiplatform>=1.70.0",
        "fastapi>=0.110.0",
        "pydantic>=2.6.0",
        "pydantic-settings>=2.2.0",
        "aiosqlite>=0.20.0",
        "httpx>=0.27.0",
    ],
)
