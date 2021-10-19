from setuptools import setup, find_packages
from Cython.Build import cythonize

setup(
    name="pygm",
    version="0.0.1",  # expected format is one of x.y.z.dev0, or x.y.z.rc1 or x.y.z (no to dashes, yes to dots)
    author="wptoux",
    author_email="wangzhen_ok@qq.com",
    description="Fast GMSSL Library for Python",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    keywords="GM SM4 Cython",
    license="Apache",
    url="https://gitee.com/wptoux/pygm",
    zip_safe=False,
    package_dir={"": "src"},
    packages=find_packages("src"),
    ext_modules = cythonize("src/pygm/*.pyx", )
)