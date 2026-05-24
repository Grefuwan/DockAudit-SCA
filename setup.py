from setuptools import setup, find_packages


def read_requirements(filename="requirements.txt"):
    with open(filename, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


setup(
    name="DockAudit-SCA",
    version="0.1.0",
    description="Docker security audit tool with SBOM and SCA integration.",
    packages=find_packages(include=["dockaudit", "dockaudit.*"]),
    install_requires=read_requirements(),
    python_requires=">=3.11",
)
