.PHONY: build dist redist install install-from-source clean uninstall

test: clean
	CYTHONIZE=1 python setup.py develop
	pytest

build:
	CYTHONIZE=1 python setup.py build

dist:
	CYTHONIZE=1 python setup.py sdist bdist_wheel

redist: clean dist

install:
	CYTHONIZE=1 pip install .

clean: uninstall
	$(RM) -r build dist src/*.egg-info
	$(RM) -r src/fastgm/*.c
	$(RM) -r .pytest_cache
	$(RM) -r src/*.so src/fastgm/*.so
	find . -name __pycache__ -exec rm -r {} +
	#git clean -fdX

uninstall:
	pip uninstall -y fastgm