(* demo.sml - derive a keypair, sign, and verify on fixed RFC 8032 Section 6
   test vectors, printing public key and signature in hex. Deterministic: same
   bytes out on every run and compiler (no RNG, no clock, hex output only). *)

fun hex s =
  let val d = "0123456789abcdef"
  in String.concat (List.map
       (fn c => let val b = Char.ord c
                in String.implode [String.sub (d, b div 16), String.sub (d, b mod 16)] end)
       (String.explode s))
  end

fun fromHex s =
  let fun n c = if c >= #"0" andalso c <= #"9" then Char.ord c - 48
                else Char.ord c - 87
  in String.implode (List.tabulate (String.size s div 2, fn i =>
       Char.chr (n (String.sub (s, i*2)) * 16 + n (String.sub (s, i*2+1))))) end

(* RFC 8032 Vector 1: 32-byte zero seed, empty message *)
val seed1 = fromHex "0000000000000000000000000000000000000000000000000000000000000000"
val {sk = sk1, pk = pk1} = Ed25519.keypair seed1
val msg1 = ""
val sig1 = Ed25519.sign sk1 msg1
val () = print "RFC 8032 Vector 1 (zero seed, empty message):\n"
val () = print ("  public key = " ^ hex pk1 ^ "\n")
val () = print ("  signature  = " ^ hex sig1 ^ "\n")
val () = print ("  verify     = " ^ Bool.toString (Ed25519.verify pk1 msg1 sig1) ^ "\n")
val () = print ("  verify(\"x\")= " ^ Bool.toString (Ed25519.verify pk1 "x" sig1) ^ "\n")

(* RFC 8032 Vector 2: 1-byte message 0x72 *)
val seed2 = fromHex "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd60f"
val {sk = sk2, pk = pk2} = Ed25519.keypair seed2
val msg2 = fromHex "72"
val sig2 = Ed25519.sign sk2 msg2
val () = print "\nRFC 8032 Vector 2 (1-byte message 0x72):\n"
val () = print ("  public key = " ^ hex pk2 ^ "\n")
val () = print ("  signature  = " ^ hex sig2 ^ "\n")
val () = print ("  verify     = " ^ Bool.toString (Ed25519.verify pk2 msg2 sig2) ^ "\n")
