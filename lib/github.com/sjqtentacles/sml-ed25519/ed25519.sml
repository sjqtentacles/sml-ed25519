(* ed25519.sml — Ed25519 digital signatures (RFC 8032).
   Pure SML over IntInf field arithmetic on the twisted Edwards curve. *)

(* ------------------------------------------------------------------ *)
(* SHA-512                                                              *)
(* ------------------------------------------------------------------ *)

structure Sha512Impl =
struct
  val k64 : Word64.word array = Array.fromList
    [ 0wx428a2f98d728ae22, 0wx7137449123ef65cd
    , 0wxb5c0fbcfec4d3b2f, 0wxe9b5dba58189dbbc
    , 0wx3956c25bf348b538, 0wx59f111f1b605d019
    , 0wx923f82a4af194f9b, 0wxab1c5ed5da6d8118
    , 0wxd807aa98a3030242, 0wx12835b0145706fbe
    , 0wx243185be4ee4b28c, 0wx550c7dc3d5ffb4e2
    , 0wx72be5d74f27b896f, 0wx80deb1fe3b1696b1
    , 0wx9bdc06a725c71235, 0wxc19bf174cf692694
    , 0wxe49b69c19ef14ad2, 0wxefbe4786384f25e3
    , 0wx0fc19dc68b8cd5b5, 0wx240ca1cc77ac9c65
    , 0wx2de92c6f592b0275, 0wx4a7484aa6ea6e483
    , 0wx5cb0a9dcbd41fbd4, 0wx76f988da831153b5
    , 0wx983e5152ee66dfab, 0wxa831c66d2db43210
    , 0wxb00327c898fb213f, 0wxbf597fc7beef0ee4
    , 0wxc6e00bf33da88fc2, 0wxd5a79147930aa725
    , 0wx06ca6351e003826f, 0wx142929670a0e6e70
    , 0wx27b70a8546d22ffc, 0wx2e1b21385c26c926
    , 0wx4d2c6dfc5ac42aed, 0wx53380d139d95b3df
    , 0wx650a73548baf63de, 0wx766a0abb3c77b2a8
    , 0wx81c2c92e47edaee6, 0wx92722c851482353b
    , 0wxa2bfe8a14cf10364, 0wxa81a664bbc423001
    , 0wxc24b8b70d0f89791, 0wxc76c51a30654be30
    , 0wxd192e819d6ef5218, 0wxd69906245565a910
    , 0wxf40e35855771202a, 0wx106aa07032bbd1b8
    , 0wx19a4c116b8d2d0c8, 0wx1e376c085141ab53
    , 0wx2748774cdf8eeb99, 0wx34b0bcb5e19b48a8
    , 0wx391c0cb3c5c95a63, 0wx4ed8aa4ae3418acb
    , 0wx5b9cca4f7763e373, 0wx682e6ff3d6b2b8a3
    , 0wx748f82ee5defb2fc, 0wx78a5636f43172f60
    , 0wx84c87814a1f0ab72, 0wx8cc702081a6439ec
    , 0wx90befffa23631e28, 0wxa4506cebde82bde9
    , 0wxbef9a3f7b2c67915, 0wxc67178f2e372532b
    , 0wxca273eceea26619c, 0wxd186b8c721c0c207
    , 0wxeada7dd6cde0eb1e, 0wxf57d4f7fee6ed178
    , 0wx06f067aa72176fba, 0wx0a637dc5a2c898a6
    , 0wx113f9804bef90dae, 0wx1b710b35131c471b
    , 0wx28db77f523047d84, 0wx32caab7b40c72493
    , 0wx3c9ebe0a15c9bebc, 0wx431d67c49c100d4c
    , 0wx4cc5d4becb3e42b6, 0wx597f299cfc657e2a
    , 0wx5fcb6fab3ad6faec, 0wx6c44198c4a475817 ]

  fun rotr (x : Word64.word) (n : Word.word) : Word64.word =
    Word64.orb (Word64.>> (x, n), Word64.<< (x, 0w64 - n))

  fun getBE64 (s : string) (off : int) : Word64.word =
    List.foldl (fn (i, acc) =>
      Word64.orb (Word64.<< (acc, 0w8),
                  Word64.fromInt (Char.ord (String.sub (s, off + i)))))
      0w0 (List.tabulate (8, fn i => i))

  fun compress (hv : Word64.word array) (blk : string) (off : int) : unit =
    let
      val w = Array.array (80, 0w0 : Word64.word)
      val () = List.app (fn i => Array.update (w, i, getBE64 blk (off + i*8)))
                        (List.tabulate (16, fn i => i))
      val () = List.app (fn i =>
          let
            val s0 = Word64.xorb (Word64.xorb
                       (rotr (Array.sub (w, i-15)) 0w1,
                        rotr (Array.sub (w, i-15)) 0w8),
                        Word64.>> (Array.sub (w, i-15), 0w7))
            val s1 = Word64.xorb (Word64.xorb
                       (rotr (Array.sub (w, i-2)) 0w19,
                        rotr (Array.sub (w, i-2)) 0w61),
                        Word64.>> (Array.sub (w, i-2), 0w6))
          in
            Array.update (w, i, Word64.+ (Word64.+ (Word64.+
              (Array.sub (w, i-16), s0), Array.sub (w, i-7)), s1))
          end)
        (List.tabulate (64, fn i => i + 16))

      val vars = Array.tabulate (8, fn i => ref (Array.sub (hv, i)))
      fun v i = Array.sub (vars, i)

      val () = List.app (fn i =>
          let
            val e  = !(v 4)
            val s1 = Word64.xorb (Word64.xorb
                       (rotr e 0w14, rotr e 0w18), rotr e 0w41)
            val ch = Word64.xorb
                       (Word64.andb (e, !(v 5)),
                        Word64.andb (Word64.notb e, !(v 6)))
            val t1 = Word64.+ (Word64.+ (Word64.+ (Word64.+
                       (!(v 7), s1), ch), Array.sub (k64, i)), Array.sub (w, i))
            val a  = !(v 0)
            val s0 = Word64.xorb (Word64.xorb
                       (rotr a 0w28, rotr a 0w34), rotr a 0w39)
            val maj = Word64.xorb (Word64.xorb
                        (Word64.andb (a, !(v 1)),
                         Word64.andb (a, !(v 2))),
                         Word64.andb (!(v 1), !(v 2)))
            val t2 = Word64.+ (s0, maj)
          in
            ( v 7 := !(v 6)
            ; v 6 := !(v 5)
            ; v 5 := !(v 4)
            ; v 4 := Word64.+ (!(v 3), t1)
            ; v 3 := !(v 2)
            ; v 2 := !(v 1)
            ; v 1 := !(v 0)
            ; v 0 := Word64.+ (t1, t2) )
          end)
        (List.tabulate (80, fn i => i))

      val () = List.app (fn i =>
          Array.update (hv, i, Word64.+ (Array.sub (hv, i), !(Array.sub (vars, i)))))
        (List.tabulate (8, fn i => i))
    in () end

  fun hash (msg : string) : string =
    let
      val hv = Array.fromList
        [ 0wx6a09e667f3bcc908, 0wxbb67ae8584caa73b
        , 0wx3c6ef372fe94f82b, 0wxa54ff53a5f1d36f1
        , 0wx510e527fade682d1, 0wx9b05688c2b3e6c1f
        , 0wx1f83d9abfb41bd6b, 0wx5be0cd19137e2179 ]
      val mlen   = String.size msg
      val bitlen = mlen * 8
      (* Padding: 0x80, zeros, 16-byte BE length (we only handle mlen < 2^61) *)
      val pad1   = String.str (Char.chr 128)
      val fill   = (112 - (mlen + 1) mod 128 + 128) mod 128
      val zeros  = String.implode (List.tabulate (fill, fn _ => #"\000"))
      (* High 8 bytes of 128-bit length = 0; low 8 bytes = bitlen *)
      val lenhi  = "\000\000\000\000\000\000\000\000"
      val lenlo  = String.implode (List.tabulate (8, fn i =>
                     Char.chr (Word64.toInt (Word64.andb
                       (Word64.>> (Word64.fromInt bitlen,
                                   Word.fromInt (56 - i*8)), 0wxff)))))
      val padded = msg ^ pad1 ^ zeros ^ lenhi ^ lenlo
      val nblk   = String.size padded div 128
      val () = List.app (fn b => compress hv padded (b * 128))
                        (List.tabulate (nblk, fn i => i))
      fun w64be w =
        String.implode (List.tabulate (8, fn i =>
          Char.chr (Word64.toInt (Word64.andb
            (Word64.>> (w, Word.fromInt (56 - i*8)), 0wxff)))))
    in
      String.concat (List.tabulate (8, fn i => w64be (Array.sub (hv, i))))
    end
end

(* ------------------------------------------------------------------ *)
(* Edwards25519 field and group arithmetic                              *)
(* ------------------------------------------------------------------ *)

structure Ed25519 : ED25519 =
struct
  val seedSize      = 32
  val publicKeySize = 32
  val secretKeySize = 64
  val signatureSize = 64

  val p : IntInf.int =
    IntInf.- (IntInf.<< (IntInf.fromInt 1, 0w255), IntInf.fromInt 19)

  val l : IntInf.int =
    0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed

  val d : IntInf.int =
    0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3

  val i_val : IntInf.int =
    0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0

  val zero = IntInf.fromInt 0
  val one  = IntInf.fromInt 1
  val two  = IntInf.fromInt 2

  fun modp x = IntInf.mod (x, p)
  fun modl x = IntInf.mod (x, l)

  fun powmod (b : IntInf.int) (e : IntInf.int) (m : IntInf.int) : IntInf.int =
    if e = zero then one
    else if IntInf.mod (e, two) = zero then
      let val h = powmod b (IntInf.div (e, two)) m
      in IntInf.mod (IntInf.* (h, h), m) end
    else IntInf.mod (IntInf.* (b, powmod b (IntInf.- (e, one)) m), m)

  fun inv x = powmod x (IntInf.- (p, two)) p

  type point = { x: IntInf.int, y: IntInf.int, z: IntInf.int, t: IntInf.int }

  val baseX : IntInf.int =
    0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
  val baseY : IntInf.int =
    0x6666666666666666666666666666666666666666666666666666666666666658

  val B : point = { x = baseX, y = baseY, z = one
                  , t = modp (IntInf.* (baseX, baseY)) }
  val O : point = { x = zero, y = one, z = one, t = zero }

  fun padd (p1 : point) (p2 : point) : point =
    let
      val {x=x1, y=y1, z=z1, t=t1} = p1
      val {x=x2, y=y2, z=z2, t=t2} = p2
      val a  = modp (IntInf.* (IntInf.- (y1, x1), IntInf.- (y2, x2)))
      val b  = modp (IntInf.* (IntInf.+ (y1, x1), IntInf.+ (y2, x2)))
      val c  = modp (IntInf.* (IntInf.* (two, t1), IntInf.* (d, t2)))
      val dd = modp (IntInf.* (IntInf.* (two, z1), z2))
      val e  = IntInf.- (b, a)
      val f  = IntInf.- (dd, c)
      val g  = IntInf.+ (dd, c)
      val h  = IntInf.+ (b, a)
    in
      { x = modp (IntInf.* (e, f))
      , y = modp (IntInf.* (g, h))
      , z = modp (IntInf.* (f, g))
      , t = modp (IntInf.* (e, h)) }
    end

  fun scalarMul (n : IntInf.int) (pt : point) : point =
    let
      fun go n pt acc =
        if n = zero then acc
        else
          let val acc' = if IntInf.mod (n, two) = one then padd acc pt else acc
          in go (IntInf.div (n, two)) (padd pt pt) acc' end
    in
      go n pt O
    end

  fun decodeIntLE (s : string) : IntInf.int =
    List.foldl (fn (i, acc) =>
      IntInf.orb (acc, IntInf.<< (IntInf.fromInt (Char.ord (String.sub (s, i))),
                                   Word.fromInt (i*8))))
      zero (List.tabulate (String.size s, fn i => i))

  fun encodeIntLE32 (n : IntInf.int) : string =
    String.implode (List.tabulate (32, fn i =>
      Char.chr (IntInf.toInt (IntInf.andb
        (IntInf.div (n, IntInf.<< (one, Word.fromInt (i*8))),
         IntInf.fromInt 255)))))

  fun encodePoint (pt : point) : string =
    let
      val zi = inv (#z pt)
      val ax = modp (IntInf.* (#x pt, zi))
      val ay = modp (IntInf.* (#y pt, zi))
      val bytes = Array.tabulate (32, fn i =>
        IntInf.toInt (IntInf.andb
          (IntInf.div (ay, IntInf.<< (one, Word.fromInt (i*8))),
           IntInf.fromInt 255)))
      (* Set top bit of byte 31 to LSB of x *)
      val sign = IntInf.toInt (IntInf.andb (ax, one))
      val () = Array.update (bytes, 31,
          Array.sub (bytes, 31) + sign * 128)
    in
      String.implode (List.tabulate (32, fn i => Char.chr (Array.sub (bytes, i))))
    end

  fun decodePoint (s : string) : point option =
    let
      val raw  = decodeIntLE s
      val sign = IntInf.toInt (IntInf.andb
                   (IntInf.div (raw, IntInf.<< (one, 0w255)), one))
      val y    = IntInf.andb (raw, IntInf.- (IntInf.<< (one, 0w255), one))
      val y2   = modp (IntInf.* (y, y))
      val u    = modp (IntInf.- (y2, one))
      val v    = modp (IntInf.+ (IntInf.* (d, y2), one))
      val x2   = modp (IntInf.* (u, inv v))
      val x0   = if x2 = zero then zero
                 else powmod x2 (IntInf.div (IntInf.+ (p, IntInf.fromInt 3),
                                              IntInf.fromInt 8)) p
      val x1   = if modp (IntInf.* (x0, x0)) = x2 then x0
                 else modp (IntInf.* (x0, i_val))
    in
      if modp (IntInf.* (x1, x1)) <> x2 then NONE
      else
        let val x = if IntInf.toInt (IntInf.andb (x1, one)) = sign
                    then x1 else IntInf.- (p, x1)
        in SOME { x = x, y = y, z = one, t = modp (IntInf.* (x, y)) }
        end
    end

  fun clampScalar (s : string) : IntInf.int =
    let
      val b = Array.tabulate (32, fn i => Char.ord (String.sub (s, i)))
      val () = Array.update (b, 0,  Word8.toInt (Word8.andb (Word8.fromInt (Array.sub (b, 0)),  0wxf8)))
      val () = Array.update (b, 31, Word8.toInt (Word8.andb (Word8.fromInt (Array.sub (b, 31)), 0wx7f)))
      val () = Array.update (b, 31, Word8.toInt (Word8.orb  (Word8.fromInt (Array.sub (b, 31)), 0wx40)))
    in
      decodeIntLE (String.implode (List.tabulate (32, fn i => Char.chr (Array.sub (b, i)))))
    end

  fun keypair (seed : string) : {sk: string, pk: string} =
    let
      val h  = Sha512Impl.hash seed
      val a  = clampScalar (String.substring (h, 0, 32))
      val pk = encodePoint (scalarMul a B)
    in
      {sk = seed ^ pk, pk = pk}
    end

  fun sign (sk : string) (msg : string) : string =
    let
      val seed   = String.substring (sk, 0, 32)
      val pk     = String.substring (sk, 32, 32)
      val h      = Sha512Impl.hash seed
      val a      = clampScalar (String.substring (h, 0, 32))
      val prefix = String.substring (h, 32, 32)
      val r      = modl (decodeIntLE (Sha512Impl.hash (prefix ^ msg)))
      val rEnc   = encodePoint (scalarMul r B)
      val k      = modl (decodeIntLE (Sha512Impl.hash (rEnc ^ pk ^ msg)))
      val s      = modl (IntInf.+ (r, IntInf.* (k, a)))
    in
      rEnc ^ encodeIntLE32 s
    end

  fun verify (pk : string) (msg : string) (sigBytes : string) : bool =
    (let
       val rEnc = String.substring (sigBytes, 0, 32)
       val R    = case decodePoint rEnc of SOME p => p | NONE => raise Fail "bad R"
       val A    = case decodePoint pk  of SOME p => p | NONE => raise Fail "bad pk"
       val s    = decodeIntLE (String.substring (sigBytes, 32, 32))
       val ()   = if s >= l then raise Fail "s out of range" else ()
       val k    = modl (decodeIntLE (Sha512Impl.hash (rEnc ^ pk ^ msg)))
       val lhs  = scalarMul s B
       val rhs  = padd R (scalarMul k A)
       val lzi  = inv (#z lhs)
       val rzi  = inv (#z rhs)
       val lx   = modp (IntInf.* (#x lhs, lzi))
       val ly   = modp (IntInf.* (#y lhs, lzi))
       val rx   = modp (IntInf.* (#x rhs, rzi))
       val ry   = modp (IntInf.* (#y rhs, rzi))
     in
       lx = rx andalso ly = ry
     end) handle Fail _ => false
end
