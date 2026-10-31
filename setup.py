from setuptools import setup, find_packages

setup(
    name="aisec-eval",
    version="0.1.0",
    description="Local-first AI security evaluation tool (Ollama).",
    author="Leen",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.8",
    install_requires=["PyYAML>=6.0"],
    entry_points={
        "console_scripts": [
            "aisec=aisec.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
