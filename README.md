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

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
derives keypairs, signs, and verifies on the fixed RFC 8032 Section 6 test
vectors, printing the public key and signature in hex:

```
$ make example
RFC 8032 Vector 1 (zero seed, empty message):
  public key = 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
  signature  = 8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803
  verify     = true
  verify("x")= false

RFC 8032 Vector 2 (1-byte message 0x72):
  public key = 9a5ba5b513ebb0feae9e36e5a12ad5d44b1481fd1a87ee1770969217394d3186
  signature  = b7f1385da825b01a227f1c71b63bfd7773bd2dcd832137cbd5ce4ce7ee5ca53d109ddd4f5c0e778bc1318cd8a02c059235275927e04bc3ee01d138c43dbb430b
  verify     = true
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
make example    # build + run the demo
```

## License

MIT
