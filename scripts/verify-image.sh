#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then echo "usage: $0 <image@sha256:digest> <github-org/repository>" >&2; exit 2; fi
image="$1"; repository="$2"
issuer='https://token.actions.githubusercontent.com'
identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/"
cosign verify --certificate-oidc-issuer "$issuer" --certificate-identity-regexp "^${identity}control-v.+$" "$image"
cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "$issuer" --certificate-identity-regexp "^${identity}control-v.+$" "$image"
echo "verified: $image"
