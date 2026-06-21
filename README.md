# sml-ed25519

Ed25519 digital signatures over Edwards25519 in pure Standard ML (RFC 8032)

## Installation

```
smlpkg add github.com/sjqtentacles/sml-ed25519
smlpkg sync
```

## Usage

```sml
(* Generate a keypair from a 32-byte seed *)
val seed = (* 32-byte random seed string *)
val {sk, pk} = Ed25519.keypair seed

(* Sign a message *)
val msg = "hello, world"
val sig = Ed25519.sign sk msg

(* Verify a signature *)
val valid = Ed25519.verify pk msg sig
(* => true *)

(* Key sizes (in bytes) *)
val _ = Ed25519.seedSize       (* 32 *)
val _ = Ed25519.publicKeySize  (* 32 *)
val _ = Ed25519.secretKeySize  (* 64 *)
val _ = Ed25519.signatureSize  (* 64 *)
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
```

## License

MIT
