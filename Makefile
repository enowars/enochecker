.PHONY: all lint diff format test

all: format test

lint:
	python3 -m isort -c src/ tests/ example/
	python3 -m black --check src/ tests/ example/
	python3 -m flake8 src/ tests/ example/
	python3 -m mypy src/ tests/ example/

diff:
	python3 -m isort --diff src/ tests/ example/
	python3 -m black --diff src/ tests/ example/

format:
	python3 -m isort src/ tests/ example/
	python3 -m black src/ tests/ example/

test:
	pip3 install .
	coverage run -m pytest
	coverage report -m
