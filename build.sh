#!/bin/sh

CYTHONIZE=1 python -m build -s
CYTHONIZE=1 python -m build -w

# python -m build