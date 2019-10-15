import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setuptools.setup(
    name="enochecker",
    version="0.0.6",
    author="domenukk",
    author_email="dmaier@sect.tu-berlin.de",
    description="Library to build checker scripts for EnoEngine A/D CTF Framework in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ENOWARS/enochecker",
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',

    ],
    zip_safe=False,  # This might be needed for reqirements.txt
)
