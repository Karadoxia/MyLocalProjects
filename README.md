# new-project

![CI](https://github.com/your-org/your-repo/actions/workflows/nodejs.yml/badge.svg)

Scaffolded Node + TypeScript starter.

## Quickstart

Install dev deps and build:

```bash
npm install
make build
make start
```

## Run (background)

Start the compiled server in background (uses port 4001):

```bash
make start-bg
```

Check health:

```bash
curl http://127.0.0.1:4001/health
```

## Tests

Run the built-in Node test runner:

```bash
make test
```

## Lint & Format

```bash
make lint
make format
```

## Docker

Build and run the Docker image locally:

```bash
make docker-build
make docker-run
```

## Rust sibling

See `new-project-rust/` for a minimal Rust starter.
