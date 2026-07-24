#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${repo_root}/dist"

for service in ingestor enricher responder; do
  (
    cd "${repo_root}/services/${service}"
    zip -X -q "${repo_root}/dist/${service}.zip" handler.py
  )
done

sha256sum "${repo_root}"/dist/*.zip
