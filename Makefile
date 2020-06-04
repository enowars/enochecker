lint:
	python -m isort -c -rc src/
	python -m black --check src/
	python -m flake8 --select F --per-file-ignores="__init__.py:F401" src/
	python -m mypy src/

format:
	python -m isort -rc src/
	python -m black src/

test:
	pip install .
	python -m pytest
