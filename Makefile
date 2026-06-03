# Local dev + e2e loop. `make test` is the fast TDD inner loop (no containers).
# `make up` then `make e2e` / `make demo` exercises the real Docker stack.

PY := .venv/bin/python

.PHONY: help venv test up down restart logs e2e demo keys seed clean

help:
	@echo "make venv   - create .venv and install requirements"
	@echo "make test   - run unit tests on the host (fast TDD loop)"
	@echo "make up     - build + start the 3-service stack (detached, waits for health)"
	@echo "make e2e    - run end-to-end tests against the running stack"
	@echo "make demo   - run the human-readable demo walkthrough"
	@echo "make logs   - tail stack logs"
	@echo "make down   - stop the stack and remove volumes"
	@echo "make clean  - remove generated keys + SQLite DBs"

venv:
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest tests/unit -q

up:
	docker compose up --build -d --wait

down:
	docker compose down -v

restart: down up

logs:
	docker compose logs -f

e2e:
	$(PY) -m pytest tests/e2e -q

demo:
	./demo.sh

keys:
	$(PY) keys/gen_keys.py

seed:
	$(PY) seed.py

clean:
	rm -f data/*.sqlite keys/*.pem keys/jwks.json
