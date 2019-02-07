import {
  runTests,
  test,
  assert,
  equal
} from "https://deno.land/x/testing/mod.ts";

import { Ed25519 } from "./mod.ts";

interface party {
  ed: Ed25519;
  seed: Uint8Array;
  sk?: Uint8Array;
  pk?: Uint8Array;
}

function xmod(buf: Uint8Array): Uint8Array {
  const cp: Uint8Array = buf.slice();
  cp[0] = ~cp[0];
  return cp;
}

const enc: TextEncoder = new TextEncoder();

test(function self() {
  assert(new Ed25519().selftest());
});

test(function generateSignVerify() {
  // alice and bob
  const a: party = {
    ed: new Ed25519(),
    seed: enc.encode("whateverwhateverwhateverwhatever")
  };
  const b: party = {
    ed: new Ed25519(),
    seed: a.seed.map((byte: number) => byte - 1)
  };
  // generating their keypairs
  Object.assign(a, a.ed.generateKeys(a.seed));
  Object.assign(b, b.ed.generateKeys(b.seed));
  // asserting key lengths
  equal(a.pk.length, 32);
  equal(b.pk.length, 32);
  equal(a.sk.length, 64);
  equal(b.sk.length, 64);
  // x-byte message
  const msg: Uint8Array = enc.encode("anansesem");
  // generating a signature
  const sig: Uint8Array = a.ed.sign(msg, a.sk, a.pk);
  equal(sig.length, 64);
  // verifying a signature
  assert(b.ed.verify(msg, a.pk, sig));
  // corrupting the verify inputs
  const xsig: Uint8Array = xmod(sig);
  const xmsg: Uint8Array = xmod(msg);
  const xapk: Uint8Array = xmod(a.pk);
  // asserting corruption resistance
  assert(!b.ed.verify(msg, a.pk, xsig));
  assert(!b.ed.verify(xmsg, a.pk, sig));
  assert(!b.ed.verify(msg, xapk, sig));
});

runTests();
