#!/bin/sh
set -e
syft packages dir:. -o cyclonedx-json=sbom.json
