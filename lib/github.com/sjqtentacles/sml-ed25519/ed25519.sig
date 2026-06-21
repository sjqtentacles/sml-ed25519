(* ed25519.sig — Ed25519 digital signatures (RFC 8032). *)

signature ED25519 =
sig
  val seedSize      : int
  val publicKeySize : int
  val secretKeySize : int
  val signatureSize : int
  val keypair : string -> {sk: string, pk: string}
  val sign    : string -> string -> string
  val verify  : string -> string -> string -> bool
end
