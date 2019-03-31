import os
import setuptools
from io import open  # for Python 2 (identical to builtin in Python 3)

repo_root = os.path.abspath(os.path.dirname(__file__))
# src = os.path.join(repo_root, "src")

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="enochecker",
    version="0.0.1",
    author="domenukk",
    author_email="dmaier@sect.tu-berlin.de",
    description="Library to build checker scripts for EnoEngine A/D CTF Framework in Python",
    long_description=long_description,
    url="https://github.com/domenukk/enochecker",
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    install_requires=requirements,
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        # 'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',

    ],
    zip_safe=False,  # This might be needed for reqirements.txt
)
