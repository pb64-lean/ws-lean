import Lake
open Lake DSL

/-!
# Editor project model

Bazel owns builds and tests. This Lake package exists only so editors and
`lake serve` can resolve the source tree.
-/

package «ws-lean» where
  leanOptions := #[⟨`experimental.module, true⟩]

require «rules-lean-grpc» from "../grpc-lean"

lean_lib «Ws» where
  srcDir := "."
  roots := #[`Ws]
