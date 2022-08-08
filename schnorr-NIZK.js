/* I am following the Schnorr NIZK for secp256k1 curve */
const crypto = require("crypto");
const secp256k1 = require('noble-secp256k1');
var assert = require('assert');

class NIZK_proof {
	constructor(t, c, s, i){
		this.t = t;
		this.c = c;
		this.s = s;
		this.i = i;
	}
}

function proof (x) {
	// Commitment keys
	const v = secp256k1.utils.randomPrivateKey();
	const V = Buffer.from(secp256k1.getPublicKey(v));

	// get the public key of the secret (Which is to be proved)
	const Q = Buffer.from(secp256k1.getPublicKey(x));

	// challenge through a Fiat-Shamir transformation.
	const challenge = crypto.createHash('sha256').update(Buffer.concat([Q,V])).digest('hex');
	const hashint = BigInt("0x"+challenge)

	// r = v - x*c % n 
	const res = BigInt("0x" + Buffer.from(v).toString('hex')) - BigInt("0x" + Buffer.from(x).toString('hex')) * hashint % secp256k1.CURVE.n;
	return new NIZK_proof(V, hashint, res, Q);
}

function verify(y){
	// Sanity checking for y
	assert (y instanceof NIZK_proof)

	// This will be needed for negative numbers
	while (y.s < BigInt("0")){
		y.s += secp256k1.CURVE.n
	}

	const ft = secp256k1.Point.BASE.multiply(y.s);
	const Qc = secp256k1.Point.fromHex(y.i).multiply(y.c);

	// lhs = V
	// rhs = G x [r] + Q x [c]
	const lhs = secp256k1.Point.fromHex(y.t);
	const rhs = ft.add(Qc)
	assert(lhs.equals(rhs))
	console.log("The private key to Q, belongs to ALice!!")
	return true
}

/* Want to prove knowledge of privkey to Bob (We're Alice) */
let x = secp256k1.utils.randomPrivateKey();

assert(verify(proof(x)))

// TODO:
// DEFINE MESSAGE TYPE FOR PROOF (with subtype for V, hashint, res, Q) and serialise and deserialise in TLV method...