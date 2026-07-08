# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — PYTHON target (atheris / libFuzzer). Builds ON TOP of the org
# C/C++ base (ghcr.io/mayhemheroes/base). The base ships CPython + pip + clang; this adds an
# in-image Python wheelhouse under /opt/toolchains/python and runs mayhem/build.sh.
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] -t cairosvg-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER root
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && apt-get install -yq --no-install-recommends \
      python3-dev python3-setuptools python3-wheel python3-venv python-is-python3 \
      libcairo2-dev libgdk-pixbuf-2.0-dev libffi-dev shared-mime-info \
      fontconfig \
    && rm -rf /var/lib/apt/lists/*
RUN install -d -o 2000 -g 2000 /opt/toolchains/python

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
