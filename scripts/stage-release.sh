#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: stage-release.sh NEW_OUTPUT_DIRECTORY" >&2
  exit 64
fi

output=$1
version=$(python3 - <<'PY'
import pathlib, tomllib

package = tomllib.loads(pathlib.Path("Cargo.toml").read_text(encoding="utf-8"))["package"]
if package["name"] != "xssc":
    raise SystemExit("Cargo.toml does not describe xssc")
print(package["version"])
PY
)
target=x86_64-unknown-linux-gnu
: "${XSSI_BUILD_TOOLS_DIR:?Provide the pinned clean xssi source checkout}"
revision=$(git rev-parse HEAD)
if [[ -n $(git status --porcelain --untracked-files=normal) ]]; then
  echo "formal release staging requires a clean source tree" >&2
  exit 1
fi
if [[ $(git describe --exact-match --match "v${version}" --tags HEAD 2>/dev/null || true) != "v${version}" ]]; then
  echo "formal release staging requires immutable tag v${version}" >&2
  exit 1
fi
if [[ $(git cat-file -t "v${version}") != tag ]]; then
  echo "formal release tag must be annotated" >&2
  exit 1
fi
if [[ -e $output ]]; then
  echo "release staging output already exists" >&2
  exit 1
fi

umask 077
mkdir -p "$output/package/bin" "$output/package/LICENSES" "$output/package/libexec" "$output/release-tools"
unset SQLITE3_LIB_DIR SQLITE3_INCLUDE_DIR LIBSQLITE3_SYS_USE_PKG_CONFIG SQLCIPHER_LIB_DIR SQLCIPHER_INCLUDE_DIR
XSSC_SOURCE_REVISION="$revision" cargo build --locked --release --target "$target"
install -m 0755 "${CARGO_TARGET_DIR:-target}/${target}/release/xssc" "$output/package/bin/xssc"
python3 scripts/stage-release-docs.py stage \
  --source-root "$PWD" --package-root "$output/package" --version "$version"
install -m 0644 LICENSE-APACHE "$output/package/LICENSES/Apache-2.0.txt"
install -m 0644 scripts/finalize-release.sh scripts/stage-release-docs.py "$output/release-tools/"
"$output/package/bin/xssc" support --json >"$output/package/adapter-catalog.json"
rustc --version --verbose >"$output/package/BUILD-ENVIRONMENT.txt"
binary_sha=$(sha256sum "$output/package/bin/xssc" | awk '{print $1}')
catalog_sha=$(sha256sum "$output/package/adapter-catalog.json" | awk '{print $1}')
capabilities=$(python3 - "$output/package/adapter-catalog.json" "$revision" "$version" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    catalog = json.load(source)
if catalog.get("formal_release_target") != "x86_64-unknown-linux-gnu":
    raise SystemExit("binary support catalog does not name the sole formal release target")
if catalog.get("compiled_target") != "x86_64-unknown-linux-gnu" or catalog.get("source_revision") != sys.argv[2] or catalog.get("tool_version") != sys.argv[3]:
    raise SystemExit("compiled binary identity differs from immutable release input")
print(json.dumps(catalog["supported_capabilities"], separators=(",", ":")))
PY
)
cat >"$output/package/release.json" <<EOF
{
  "product": "xssc",
  "version": "${version}",
  "source_revision": "${revision}",
  "target": "${target}",
  "rust_version": "1.99.0",
  "binary_sha256": "${binary_sha}",
  "catalog_sha256": "${catalog_sha}",
  "release_manifest_versions": [1],
  "upgrade_journal_version": 1,
  "release_upgrade_protocol": "fixed-root-payload-v1",
  "supported_capabilities": ${capabilities}
}
EOF
builder=local-controlled-build
if [[ ${GITHUB_ACTIONS:-false} == true ]]; then
  builder=github-actions/ubuntu-24.04
fi
cat >"$output/package/provenance.json" <<EOF
{
  "builder": "${builder}",
  "source_revision": "${revision}",
  "subject_sha256": "${binary_sha}",
  "target": "${target}",
  "build_type": "xssc/formal-release-v1"
}
EOF
find "$output/package" -type d -exec chmod 0755 {} +
find "$output/package" -type f -exec chmod 0644 {} +
chmod 0755 "$output/package/bin/xssc" "$output/release-tools/finalize-release.sh"
python3 scripts/write-sbom.py --stage "$output/package" --tools "$XSSI_BUILD_TOOLS_DIR" \
  --source-revision "$revision" --target "$target"
install -m 0644 "$XSSI_BUILD_TOOLS_DIR/scripts/release_manifest.py" \
  "$XSSI_BUILD_TOOLS_DIR/scripts/release_sbom.py" "$output/release-tools/"
