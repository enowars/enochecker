lint:
	python -m isort -c -rc src/ tests/
	python -m black --check src/ tests/
	python -m flake8 --select F --per-file-ignores="__init__.py:F401" src/ tests/
	python -m mypy src/ tests/

format:
	python -m isort -rc src/ tests/
	python -m black src/ tests/

test:
	pip install .
	coverage run -m pytest
	coverage report -m
