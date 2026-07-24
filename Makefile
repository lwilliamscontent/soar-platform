.PHONY: test test-exercises format terraform-validate playground-up playground-down exercise

test:
	python3 -m pytest -q

test-exercises:
	python3 -m pytest tests/test_playground.py -q

format:
	terraform -chdir=infra/terraform fmt -recursive

terraform-validate:
	terraform -chdir=infra/terraform init -backend=false
	terraform -chdir=infra/terraform validate

playground-up:
	docker compose up -d

playground-down:
	docker compose down

exercise:
	./scripts/run-local-exercise.sh
