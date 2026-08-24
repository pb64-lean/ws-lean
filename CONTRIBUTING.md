# Contributing

This project is pre-release, so public APIs may still be refined. Compatibility
and migration consequences must nevertheless be made explicit.

Use the dependency checkout layout expected by `MODULE.bazel`, then run the
authoritative checks from this repository's root:

```sh
bazel build //...
bazel test //...
```

Lake exists only for editor feedback and does not replace Bazel validation.
After an intentional dependency change, refresh the module lock through the
actual build graph and review the complete diff:

```sh
bazel build --lockfile_mode=update //... \
  //Conformance:echo_server //Conformance:load_client
```

Protocol changes require focused split-point and malformed-peer tests. Changes
to framing, handshakes, compression, flow control, or shutdown also require the
applicable interoperability suite. Keep parsers bounded, preserve transport
leftovers, and use typed failures rather than silently accepting malformed
wire input.

Security reports belong in the private channel described in
[SECURITY.md](SECURITY.md). Participation is governed by
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contributions are licensed under the
[Apache License 2.0](LICENSE).
