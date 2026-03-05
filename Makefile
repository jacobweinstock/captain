.PHONY: lint fmt lint-install

lint-install:
	pip install -r requirements-dev.txt

lint:
	ruff check .
	ruff format --check .
	pyright .

fmt:
	ruff check --fix .
	ruff format .
