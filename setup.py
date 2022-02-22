import os
from sys import version_info

from setuptools import setup, Extension, find_packages

try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = None

if version_info[0] == 2:
    from io import open


# https://cython.readthedocs.io/en/latest/src/userguide/source_files_and_compilation.html#distributing-cython-modules
def no_cythonize(extensions, **_ignore):
    for extension in extensions:
        sources = []
        for sfile in extension.sources:
            path, ext = os.path.splitext(sfile)
            if ext in (".pyx", ".py"):
                if extension.language == "c++":
                    ext = ".cpp"
                else:
                    ext = ".c"
                sfile = path + ext
            sources.append(sfile)
        extension.sources[:] = sources
    return extensions


extensions = [
    Extension(
        'fastgm.sm4',
        sources=['src/fastgm/sm4.pyx'],
    ),
    Extension(
        'fastgm.sm3',
        sources=['src/fastgm/sm3.pyx'],
    )
]

CYTHONIZE = bool(int(os.getenv("CYTHONIZE", 0))) and cythonize is not None

if CYTHONIZE:
    compiler_directives = {"language_level": version_info[0], "embedsignature": True}
    extensions = cythonize(extensions, compiler_directives=compiler_directives)
else:
    extensions = no_cythonize(extensions)

setup(
    name="fastgm",
    version="0.4.1",  # expected format is one of x.y.z.dev0, or x.y.z.rc1 or x.y.z (no to dashes, yes to dots)
    author="wptoux",
    author_email="wangzhen_ok@qq.com",
    description="Fast GMSSL Library for Python",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    keywords="国密, GM, GMSSL, SM2, SM3, SM4, Cython",
    license="Apache",
    url="https://github.com/wptoux/fastgm",
    zip_safe=False,
    package_dir={"": "src"},
    packages=find_packages("src"),
    ext_modules=extensions,
    options={"bdist_wheel": {"universal": True}},
    python_requires='>=2.6, <4',
    classifiers=[  
        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate you support Python 3. These classifiers are *not*
        # checked by 'pip install'. See instead 'python_requires' below.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
)
