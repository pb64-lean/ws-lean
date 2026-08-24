module

public import Ws.Basic
public import Ws.PerMessageDeflate.Negotiation
public import Ws.PerMessageDeflate.Raw

public section

namespace Ws.PerMessageDeflate

/-- Two independent persistent streams.  The connection writer exclusively
owns `compressor`; the connection reader exclusively owns `inflater`.  They are
joined before `close`, preserving the native contexts' thread-confinement
contract without a blocking mutex around zlib. -/
structure Session where
  private mk ::
  role : Role
  parameters : Parameters
  private compressor : Raw.Context
  private inflater : Raw.Context

private def outboundWindow (role : Role) (parameters : Parameters) : UInt8 :=
  match role with
  | .client => parameters.clientMaxWindowBits
  | .server => parameters.serverMaxWindowBits

private def inboundWindow (role : Role) (parameters : Parameters) : UInt8 :=
  match role with
  | .client => parameters.serverMaxWindowBits
  | .server => parameters.clientMaxWindowBits

private def outboundNoTakeover (role : Role) (parameters : Parameters) : Bool :=
  match role with
  | .client => parameters.clientNoContextTakeover
  | .server => parameters.serverNoContextTakeover

private def inboundNoTakeover (role : Role) (parameters : Parameters) : Bool :=
  match role with
  | .client => parameters.serverNoContextTakeover
  | .server => parameters.clientNoContextTakeover

/-- Allocate both halves transactionally.  If the inflater cannot be created,
the already-created compressor is closed before the error is returned. -/
def Session.create (role : Role) (parameters : Parameters) :
    IO (Except Raw.Error Session) := do
  let compressorResult ← Raw.create .compress (outboundWindow role parameters)
  match compressorResult with
  | .error error => pure (.error error)
  | .ok compressor =>
      let inflaterResult ← Raw.create .decompress (inboundWindow role parameters)
      match inflaterResult with
      | .ok inflater => pure (.ok { role, parameters, compressor, inflater })
      | .error error =>
          compressor.close
          pure (.error error)

/-- Compress one complete message. `maxOutput` bounds even worst-case expansion. -/
def Session.compress (session : Session) (message : ByteArray) (maxOutput : UInt64) :
    IO (Except Raw.Error ByteArray) :=
  Raw.process session.compressor message maxOutput
    (outboundNoTakeover session.role session.parameters)

/-- Inflate one complete message with a decompression-bomb bound. -/
def Session.decompress (session : Session) (message : ByteArray) (maxOutput : UInt64) :
    IO (Except Raw.Error ByteArray) :=
  Raw.process session.inflater message maxOutput
    (inboundNoTakeover session.role session.parameters)

/-- Deterministically release both streams. Repeated calls are safe. -/
def Session.close (session : Session) : IO Unit := do
  session.compressor.close
  session.inflater.close

end Ws.PerMessageDeflate
