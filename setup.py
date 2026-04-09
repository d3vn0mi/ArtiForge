from setuptools import setup, find_packages

setup(
    name="artiforge",
    version="0.4.0",
    author="D3vn0mi",
    author_email="",
    description="YAML-driven Windows event artifact generator for cybersecurity training labs.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/D3vn0mi/ArtiForge",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Education",
        "Environment :: Console",
    ],
    packages=find_packages(),
    include_package_data=True,
    package_data={"artiforge": ["labs/**/*.yaml", "labs/**/*.xml", "labs/**/*.md", "labs/**/*.json"]},
    install_requires=[
        "click>=8.1",
        "pyyaml>=6.0",
        "pydantic>=2.0",
    ],
    entry_points={
        "console_scripts": [
            "artiforge=artiforge.cli:main",
        ],
    },
    python_requires=">=3.10",
)
