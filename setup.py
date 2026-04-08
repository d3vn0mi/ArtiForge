from setuptools import setup, find_packages

setup(
    name="artiforge",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={"artiforge": ["labs/**/*.yaml", "labs/**/*.xml"]},
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
