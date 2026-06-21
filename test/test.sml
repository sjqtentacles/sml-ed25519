(* test.sml - Ed25519 test suite.
   Test vectors from RFC 8032 Section 6. *)

structure Ed25519Tests =
struct
  open Harness

  (* Build a string from a hex string *)
  fun fromHex (s : string) : string =
    let
      fun nibble c =
        if c >= #"0" andalso c <= #"9" then Char.ord c - 48
        else if c >= #"a" andalso c <= #"f" then Char.ord c - 87
        else raise Fail ("bad hex char: " ^ String.str c)
      val n = String.size s
      val _ = if n mod 2 <> 0 then raise Fail "odd hex length" else ()
    in
      String.implode (List.tabulate (n div 2, fn i =>
        Char.chr (nibble (String.sub (s, i*2)) * 16 +
                  nibble (String.sub (s, i*2 + 1)))))
    end

  fun runConstants () =
    let
      val () = section "Ed25519 constants"
      val () = checkInt "seedSize"      (32, Ed25519.seedSize)
      val () = checkInt "publicKeySize" (32, Ed25519.publicKeySize)
      val () = checkInt "secretKeySize" (64, Ed25519.secretKeySize)
      val () = checkInt "signatureSize" (64, Ed25519.signatureSize)
    in () end

  fun runVector1 () =
    let
      val () = section "RFC 8032 Vector 1 (empty message)"
      val seed = fromHex "0000000000000000000000000000000000000000000000000000000000000000"
      val {sk, pk} = Ed25519.keypair seed
      val () = checkString "public key"
        ( "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        , let val hex = "0123456789abcdef"
          in String.concat (List.tabulate (32, fn i =>
               let val b = Char.ord (String.sub (pk, i))
               in String.implode [String.sub (hex, b div 16), String.sub (hex, b mod 16)]
               end))
          end )
      val sigB = Ed25519.sign sk ""
      val () = check "signature length = 64" (String.size sigB = 64)
      val () = check "verify succeeds" (Ed25519.verify pk "" sigB)
      val () = check "verify fails on wrong message" (not (Ed25519.verify pk "x" sigB))
    in () end

  fun runVector2 () =
    let
      val () = section "RFC 8032 Vector 2 (1-byte message)"
      val seed = fromHex "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd60f"
      val {sk, pk} = Ed25519.keypair seed
      val msg  = fromHex "72"
      val sigB = Ed25519.sign sk msg
      val () = check "verify succeeds" (Ed25519.verify pk msg sigB)
      val () = check "verify fails on empty message" (not (Ed25519.verify pk "" sigB))
      val () = check "sig length = 64" (String.size sigB = 64)
    in () end

  fun runVector3 () =
    let
      val () = section "RFC 8032 Vector 3 (2-byte message)"
      val seed = fromHex "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
      val {sk, pk} = Ed25519.keypair seed
      val msg  = fromHex "af82"
      val sigB = Ed25519.sign sk msg
      val () = check "verify succeeds" (Ed25519.verify pk msg sigB)
      val () = check "wrong sig fails"
        (not (Ed25519.verify pk msg
          (String.substring (sigB, 0, 63) ^
           String.str (Char.chr ((Char.ord (String.sub (sigB, 63)) + 1) mod 256)))))
    in () end

  fun runMisc () =
    let
      val () = section "Misc properties"
      val seed1 = String.implode (List.tabulate (32, fn i => Char.chr i))
      val seed2 = String.implode (List.tabulate (32, fn i => Char.chr (i + 1)))
      val {sk=sk1, pk=pk1} = Ed25519.keypair seed1
      val {sk=sk2, pk=pk2} = Ed25519.keypair seed2
      val () = check "different seeds give different keys" (pk1 <> pk2)
      val msg = "Hello, Ed25519!"
      val sig1 = Ed25519.sign sk1 msg
      val sig2 = Ed25519.sign sk2 msg
      val () = check "sig with key1 verifies under key1" (Ed25519.verify pk1 msg sig1)
      val () = check "sig with key2 verifies under key2" (Ed25519.verify pk2 msg sig2)
      val () = check "sig with key1 fails under key2" (not (Ed25519.verify pk2 msg sig1))
      val () = check "sig with key2 fails under key1" (not (Ed25519.verify pk1 msg sig2))
    in () end

  fun run () =
    ( runConstants ()
    ; runVector1 ()
    ; runVector2 ()
    ; runVector3 ()
    ; runMisc () )
end
