# External protocol conformance

The manual echo server is intended for wire-level interoperability testing. It
accepts plaintext WebSocket connections on loopback, echoes text and binary
messages, and negotiates `permessage-deflate` when offered.

Build and start it directly with:

```sh
bazel run //Conformance:echo_server -- 9001
```

The pinned Autobahn Testsuite runner exercises every RFC case except category
9, whose cases are explicitly limits/performance workloads. Categories 12 and
13 exercise `permessage-deflate` payloads and negotiation parameters.

```sh
Conformance/run-autobahn-server.sh
```

For an isolated compression run, select the focused specification:

```sh
AUTOBAHN_SPEC="$PWD/Conformance/autobahn-pmd.json" \
  Conformance/run-autobahn-server.sh
```

Reports are written to a temporary directory printed by the script, never to
the source tree. Set `AUTOBAHN_REPORT_DIR` to retain them at a chosen location:

```sh
AUTOBAHN_REPORT_DIR=/tmp/ws-conformance Conformance/run-autobahn-server.sh
```

At completion, `summarize-autobahn.py` prints exact behavior and close-behavior
counts. It exits unsuccessfully for failed, non-strict, unimplemented, unclean,
or wrong-code cases and prints the corresponding case details.

The runner requires Docker and uses Autobahn Testsuite version `25.10.1` with
host networking, pinned immutably to container digest
`sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074`.
