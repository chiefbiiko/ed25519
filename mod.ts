import { Curve25519 } from './../curve25519/mod.ts';
import { SHA512 } from './../sha512/mod.ts';
import { compare, hex2bin, Signature } from './utils.ts';

///////////////////////////////////////////////////////////////////////////////
// E D 2 5 5 1 9

/**
 * Ed25519 class
 */
export class Ed25519 implements Signature {
  curve:  Curve25519;
  sha512: SHA512;
  X:      Int32Array;
  Y:      Int32Array;
  L:      Uint8Array;


  /**
   * Ed25519 ctor
   */
  constructor() {
    this.curve  = new Curve25519();
    this.sha512 = new SHA512();
    this.X = this.curve.gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]);
    this.Y = this.curve.gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]);
    this.L = new Uint8Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
  }


  private pack(r: Uint8Array, p: Array<Int32Array>): void {
    let CURVE = this.curve;
    let tx = CURVE.gf(),
        ty = CURVE.gf(),
        zi = CURVE.gf();
    CURVE.inv25519(zi, p[2]);
    CURVE.M(tx, p[0], zi);
    CURVE.M(ty, p[1], zi);
    CURVE.pack25519(r, ty);
    r[31] ^= CURVE.par25519(tx) << 7;
  }


  private modL(r: Uint8Array, x: Uint32Array): void {
    let carry, i, j, k;
    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32, k = i - 12; j < k; ++j) {
        x[j] += carry - 16 * x[i] * this.L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;                // caution: NO >>> here, carry is needed!!!
        x[j] -= carry * 256;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * this.L[j];   // caution: NO >>> here, carry is needed!!!
      carry = x[j] >> 8;                          // caution: NO >>> here, carry is needed!!!
      x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * this.L[j];
    for (i = 0; i < 32; i++) {
      x[i + 1] += x[i] >>> 8;
      r[i] = x[i] & 0xff;
    }
  }


  private reduce(r: Uint8Array): void {
    let i, x = new Uint32Array(64);
    for (i = 0; i < 64; i++) {
      x[i] = r[i];
    }
    this.modL(r, x);
  }


  private scalarmult(p: Array<Int32Array>, q: Array<Int32Array>, s: Uint8Array): void {
    let CURVE = this.curve;
    CURVE.set25519(p[0], CURVE.gf0);
    CURVE.set25519(p[1], CURVE.gf1);
    CURVE.set25519(p[2], CURVE.gf1);
    CURVE.set25519(p[3], CURVE.gf0);
    for (let i = 255; i >= 0; --i) {
      let b = (s[(i / 8) | 0] >>> (i & 7)) & 1;
      CURVE.cswap(p, q, b);
      CURVE.add(q, p);
      CURVE.add(p, p);
      CURVE.cswap(p, q, b);
    }
  }


  private scalarbase(p: Array<Int32Array>, s: Uint8Array): void {
    let CURVE = this.curve;
    let q = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];
    CURVE.set25519(q[0], this.X);
    CURVE.set25519(q[1], this.Y);
    CURVE.set25519(q[2], CURVE.gf1);
    CURVE.M(q[3], this.X, this.Y);
    this.scalarmult(p, q, s);
  }


  /**
   * Generate an ed25519 keypair
   * Some implementations represent the secret key as a combination of sk and pk. mipher just uses the sk itself.
   * @param {Uint8Array} seed A 32 byte cryptographic secure random array. This is basically the secret key
   * @param {Object} Returns sk (Secret key) and pk (Public key) as 32 byte typed arrays
   */
  generateKeys(seed: Uint8Array): { sk: Uint8Array, pk: Uint8Array } {
    let sk = seed.slice();
    let pk = new Uint8Array(32);
    if (sk.length !== 32) {
      return;
    }

    let p = [this.curve.gf(), this.curve.gf(), this.curve.gf(), this.curve.gf()];
    let h = this.sha512.hash(sk).subarray(0, 32);

    // harden the secret key by clearing bit 0, 1, 2, 255 and setting bit 254
    // clearing the lower 3 bits of the secret key ensures that is it a multiple of 8
    h[0]  &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    this.scalarbase(p, h);
    this.pack(pk, p);
    return { sk: sk, pk: pk };
  }


  /**
   * Generate a message signature
   * @param {Uint8Array} msg Message to be signed as byte array
   * @param {Uint8Array} sk Secret key as 32 byte array
   * @param {Uint8Array} pk Public key as 32 byte array
   * @param {Uint8Array} Returns the signature as 64 byte typed array
   */
  sign(msg: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array {
    let CURVE = this.curve;
    let p = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];
    let h = this.sha512.hash(sk);

    if (sk.length !== 32) return;
    if (pk.length !== 32) return;

    h[ 0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    // compute r = SHA512(h[32-63] || M)
    let s = new Uint8Array(64);
    let r = this.sha512.init().update(h.subarray(32)).digest(msg);
    this.reduce(r);
    this.scalarbase(p, r);
    this.pack(s, p);

    // compute k = SHA512(R || A || M)
    let k = this.sha512.init().update(s.subarray(0, 32)).update(pk).digest(msg);
    this.reduce(k);

    // compute s = (r + k a) mod q
    let x = new Uint32Array(64), i, j;
    for (i = 0; i < 32; i++) x[i] = r[i];
    for (i = 0; i < 32; i++) {
      for (j = 0; j < 32; j++) {
        x[i + j] += k[i] * h[j];
      }
    }
    this.modL(s.subarray(32), x);

    return s;
  }


  /**
   * Verify a message signature
   * @param {Uint8Array} msg Message to be signed as byte array
   * @param {Uint8Array} pk Public key as 32 byte array
   * @param {Uint8Array} sig Signature as 64 byte array
   * @param {Boolean} Returns true if signature is valid
   */
  verify(msg: Uint8Array, pk: Uint8Array, sig: Uint8Array): boolean {
    let CURVE = this.curve;
    let p = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()],
        q = [CURVE.gf(), CURVE.gf(), CURVE.gf(), CURVE.gf()];

    if (sig.length !== 64) return false;
    if (pk.length !== 32) return false;
    if (CURVE.unpackNeg(q, pk)) return false;

    // compute k = SHA512(R || A || M)
    let k = this.sha512.init().update(sig.subarray(0, 32)).update(pk).digest(msg);
    this.reduce(k);
    this.scalarmult(p, q, k);

    let t = new Uint8Array(32);
    this.scalarbase(q, sig.subarray(32));
    CURVE.add(p, q);
    this.pack(t, p);

    return compare(sig.subarray(0, 32), t);
  }


  /**
   * Performs a quick selftest
   * @param {Boolean} Returns true if selftest passed
   */
  selftest(): boolean {
    const v = [
      { sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        m : '',
        s : 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' },
      { sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
        pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
        m : '72',
        s : '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00' },
      { sk: '5b5a619f8ce1c66d7ce26e5a2ae7b0c04febcd346d286c929e19d0d5973bfef9',
        pk: '6fe83693d011d111131c4f3fbaaa40a9d3d76b30012ff73bb0e39ec27ab18257',
        m : '5a8d9d0a22357e6655f9c785',
        s : '0f9ad9793033a2fa06614b277d37381e6d94f65ac2a5a94558d09ed6ce922258c1a567952e863ac94297aec3c0d0c8ddf71084e504860bb6ba27449b55adc40e' }
    ];

    for (let i = 0; i < v.length; i++) {
      let sk = hex2bin(v[i].sk),
          pk = hex2bin(v[i].pk),
          m  = hex2bin(v[i].m),
          s  = hex2bin(v[i].s);

      // sign test
      if (!compare(this.sign(m, sk, pk), s)) return false;

      // verify test
      if (!this.verify(m, pk, s)) return false;
      s[i % 64] ^= 0x01;
      if (this.verify(m, pk, s)) return false;
    }

    return true;
  }
}
