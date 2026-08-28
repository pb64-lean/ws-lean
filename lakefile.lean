import Lake
open Lake DSL

/-!
# Editor project model

Bazel owns builds and tests. This Lake package exists only so editors and
`lake serve` can resolve the source tree.
-/

package «ws-lean» where
  leanOptions := #[⟨`experimental.module, true⟩]

require «http2-lean» from git
  "https://github.com/pb64-lean/http2-lean.git" @
  "82fc066025f3e5fdec54c836f4e9659c2f8176ab"

@[default_target]
lean_lib «Ws» where
  srcDir := "."
  roots := #[`Ws]
