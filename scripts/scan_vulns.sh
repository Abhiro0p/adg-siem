#!/bin/sh
set -e
trivy fs --severity HIGH,CRITICAL --ignore-unfixed .
