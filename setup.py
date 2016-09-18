#!/usr/bin/env python

from setuptools import setup

setup(name="qca_hex_analyzer",
      version="0.1",
      description="A library/tool for analyzing qca radio driver hexdumps from log files",
      url="https://github.com/erstrom/qca_hex_analyzer",
      author="Erik Stromdahl",
      author_email="erik.stromdahl@gmail.com",
      license="MIT",
      long_description="\n",
      entry_points={
        "console_scripts": ["qca_hex_analyzer=qca_hex_analyzer.__main__:main"]
      },
      packages=["qca_hex_analyzer"],
      classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Topic :: Software Development"
      ],
      install_requires=[
          'hexfilter',
      ]
)
