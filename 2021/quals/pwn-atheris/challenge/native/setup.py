# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Ian Eldred Pudney

import os
import shutil
import subprocess
import sys
import tempfile

import setuptools
from setuptools import Extension
from setuptools import setup
from setuptools.command.build_ext import build_ext

__version__ = "1.0.0"

if len(sys.argv) > 1 and sys.argv[1] == "print_version":
  print(__version__)
  quit()


ext_modules = [
    Extension(
        "turbozipfile",
        sorted([
            "turbozipfile.c",
        ]),
        include_dirs=[
        ],
        language="c++"),
]


class BuildExt(build_ext):
  """A custom build extension for adding compiler-specific options."""

  def build_extensions(self):
    c_opts = []
    l_opts = []

    if sys.platform == "darwin":
      darwin_opts = ["-stdlib=libc++", "-mmacosx-version-min=10.7"]
      c_opts += darwin_opts
      l_opts += darwin_opts

    ct = self.compiler.compiler_type

    for ext in self.extensions:
      ext.define_macros = [("VERSION_INFO",
                            "'{}'".format(self.distribution.get_version()))]
      ext.extra_compile_args = c_opts
      ext.extra_link_args = l_opts
    build_ext.build_extensions(self)


setup(
    name="turbozipfile",
    version=__version__,
    author="Ian Eldred Pudney",
    author_email="puddles@google.com",
    url="https://capturetheflag.withgoogle.com/",
    description="DO NOT USE THIS PACKAGE - this exists for a CTF challenge. It has known bugs.",
    long_description="DO NOT USE THIS PACKAGE - this exists for a CTF challenge. It has known bugs.",
    long_description_content_type="text/markdown",
    ext_modules=ext_modules,
    setup_requires=[],
    cmdclass={"build_ext": BuildExt},
    zip_safe=False,
)
