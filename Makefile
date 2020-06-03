lint:
	python -m isort -c -rc src/
	python -m black --check src/

format:
	python -m isort -rc src/
	python -m black src/

test:
	pip install .
	python -m pytest
