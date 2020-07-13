lint:
	python3 -m isort -c -rc src/ tests/ example/
	python3 -m black --check src/ tests/ example/
	python3 -m flake8 --select F --per-file-ignores="__init__.py:F401" src/ tests/ example/
	python3 -m mypy src/ tests/ example/

format:
	python3 -m isort -rc src/ tests/ example/
	python3 -m black src/ tests/ example/

test:
	pip install .
	coverage run -m pytest
	coverage report -m
