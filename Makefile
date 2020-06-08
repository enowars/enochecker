lint:
	python -m isort -c -rc src/ tests/ example/
	python -m black --check src/ tests/ example/
	python -m flake8 --select F --per-file-ignores="__init__.py:F401" src/ tests/ example/
	python -m mypy src/ tests/ example/

format:
	python -m isort -rc src/ tests/ example/
	python -m black src/ tests/ example/

test:
	pip install .
	coverage run -m pytest
	coverage report -m
