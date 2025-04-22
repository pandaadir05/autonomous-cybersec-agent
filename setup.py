#!/usr/bin/env python3
"""
Setup script for the Autonomous Cybersecurity Agent.
"""

from setuptools import setup, find_packages

setup(
    name="lesh-cybersec-agent",
    version="0.1.0",
    description="Autonomous Cybersecurity Defense Agent",
    author="Adir Shitrit",
    author_email="admin@example.com",
    python_requires=">=3.8",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "numpy>=1.19.0",
        "pandas>=1.0.0",
        "scikit-learn>=0.23.0",
        "dash>=2.8.0",
        "dash-bootstrap-components>=1.4.0",
        "plotly>=5.13.0",
        "fastapi>=0.95.0",
        "uvicorn>=0.21.0",
        "python-dotenv>=0.21.0",
        "pyyaml>=6.0",
        "requests>=2.25.0",
        "joblib>=1.1.0",
        "psutil>=5.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "isort>=5.10.0",
            "pylint>=2.10.0",
            "coverage>=6.0.0",
        ],
        "ml": [
            "tensorflow>=2.8.0",
            "torch>=1.10.0",
            "shap>=0.40.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "lesh-agent=run:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
)
