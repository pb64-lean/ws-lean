#!/usr/bin/env bash
set -euo pipefail

readonly image_version="25.10.1"
readonly image_digest="sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
readonly image="crossbario/autobahn-testsuite@${image_digest}"
readonly root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly report_dir="${AUTOBAHN_REPORT_DIR:-$(mktemp -d)}"
readonly spec_file="${AUTOBAHN_SPEC:-${root_dir}/Conformance/autobahn-server.json}"
readonly server_log="${report_dir}/echo-server.log"

mkdir -p "${report_dir}"

cd "${root_dir}"
bazel build //Conformance:echo_server
"${root_dir}/bazel-bin/Conformance/echo_server" 9001 >"${server_log}" 2>&1 &
server_pid=$!

cleanup() {
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ready=false
for _ in $(seq 1 100); do
  if grep -q "listening" "${server_log}"; then
    ready=true
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    cat "${server_log}" >&2
    exit 1
  fi
  sleep 0.05
done

if [[ "${ready}" != true ]]; then
  printf 'echo server did not become ready\n' >&2
  cat "${server_log}" >&2
  exit 1
fi

runner_status=0
printf 'Autobahn image: crossbario/autobahn-testsuite:%s (%s)\n' \
  "${image_version}" "${image_digest}"
docker run --rm --network host \
  -v "${spec_file}:/config/fuzzingclient.json:ro" \
  -v "${report_dir}:/reports" \
  "${image}" \
  wstest --mode fuzzingclient --spec /config/fuzzingclient.json || runner_status=$?

summary_status=0
python3 "${root_dir}/Conformance/summarize-autobahn.py" \
  "${report_dir}/index.json" || summary_status=$?

printf 'Autobahn reports: %s\n' "${report_dir}"
printf 'Server log: %s\n' "${server_log}"

if (( runner_status != 0 )); then
  exit "${runner_status}"
fi
exit "${summary_status}"
