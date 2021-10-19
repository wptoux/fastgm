from distutils.core import setup
from setuptools import find_packages, Extension

# from Cython.Build import cythonize
import Cython
import Cython.Build

extensions = [
    Extension(
        '*',
        sources=['src/fastgm/*.pyx'],
        include_dirs = [],
        extra_compile_args=[],
    )
]

setup(
    name="fastgm",
    version="0.0.1",  # expected format is one of x.y.z.dev0, or x.y.z.rc1 or x.y.z (no to dashes, yes to dots)
    author="wptoux",
    author_email="wangzhen_ok@qq.com",
    description="Fast GMSSL Library for Python",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    keywords="GM SM4 Cython",
    license="Apache",
    url="https://gitee.com/wptoux/fastgm",
    zip_safe=False,
    package_dir={"": "src"},
    packages=find_packages("src"),
    extensions=extensions,
    cmdclass={'build_ext': Cython.Build.build_ext}
)