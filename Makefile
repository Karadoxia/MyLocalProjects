.PHONY: build start start-bg docker-build docker-run test lint format

build:
	npm run build

start:
	npm run start

start-bg:
	npm run start-bg

docker-build:
	docker build -t new-project:local .
	docker image ls new-project:local || true

docker-run:
	docker run --rm -d --name new-project-local -p 4002:4001 new-project:local
	sleep 1
	curl -sS http://127.0.0.1:4002/health || true
	docker rm -f new-project-local || true

test:
	npm test

lint:
	npx eslint "src/**/*.ts" --ext .ts || true

format:
	npx prettier --write .
