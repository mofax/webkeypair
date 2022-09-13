const crypto = globalThis.crypto ? globalThis.crypto : require('node:crypto')
const subtle = crypto.subtle;

export const NAMED_CURVE = "P-256" as const;
export const ADDRESS_PREFIX = "0xx1" as const;
export const EC_NAME = "ECDSA" as const;
export const SHA_DEFAULT = "SHA-256" as const;

function assert(check: boolean, message?: string) {
	if(!check) {
		const msg = message || "";
		throw new Error(`assertion error: ${msg}`)
	}
}

function byteArraytoHexString(byteArray: Uint8Array) {
	return Array.prototype.map.call(byteArray, function(byte) {
	  return ('0' + (byte & 0xFF).toString(16)).slice(-2);
	}).join('');
}

function hexStringtoByteArray(hexString: string) {
	if(hexString.length % 2 !== 0) {
		throw new Error('Invalid hex string');
	}
	let result: number[] = [];
	for (var i = 0; i < hexString.length; i += 2) {
		const parsed = parseInt(hexString.substr(i, 2), 16);
		result.push(parsed);
	}
	return new Uint8Array(result);
}

async function sha256Digest(data: Uint8Array) {
	const digest = await subtle.digest("SHA-256", data);
	return new Uint8Array(digest);
}

export async function publicKeyToAddress(key: CryptoKey) {
	assert(key.type === "public");
	assert(key.algorithm.name === EC_NAME);

	const exportedKey = await subtle.exportKey("raw", key);
	const exportedKeyBuffer = new Uint8Array(exportedKey);

	const hashDigest = await sha256Digest(exportedKeyBuffer)

	// assert length of hashDigest is 32 bytes
	assert(hashDigest.length === 32);

	// get the first 20 bytes of the hash
	const address = hashDigest.subarray(0, 20);

	const addressHex = byteArraytoHexString(address);
	return `${ADDRESS_PREFIX}${addressHex}`;
}

export async function generateKeyPair() {
	const result = await subtle.generateKey(
		{
			name: "ECDSA",
			namedCurve: NAMED_CURVE,
		},
		true,
		["sign", "verify"]
	);

	return result;
}

export async function exportKeyPair(keyPair: CryptoKeyPair) {
	const privateKeyPromise = subtle.exportKey("jwk", keyPair.privateKey);
	const publicKeyPromise = subtle.exportKey("jwk", keyPair.publicKey);

	const [privateKey, publicKey] = await Promise.all([privateKeyPromise, publicKeyPromise]);

	return { privateKey, publicKey };
}

export async function importKeyPair(keyPair: {
	privateKey: JsonWebKey;
	publicKey: JsonWebKey;
}): Promise<CryptoKeyPair> {
	const privateKeyPromise = subtle.importKey(
		"jwk",
		keyPair.privateKey,
		{
			name: EC_NAME,
			namedCurve: NAMED_CURVE,
		},
		true,
		["sign"]
	);

	const publicKeyPromise = subtle.importKey(
		"jwk",
		keyPair.publicKey,
		{
			name: EC_NAME,
			namedCurve: NAMED_CURVE,
		},
		true,
		["verify"]
	);

	const [privateKey, publicKey] = await Promise.all([privateKeyPromise, publicKeyPromise]);

	return { privateKey, publicKey };
}

export async function signObject(key: CryptoKey, object: unknown) {
	assert(key.type === "private");
	assert(key.algorithm.name === EC_NAME);

	const message = JSON.stringify(object);
	const textEncoder = new TextEncoder();
	const encodedView = textEncoder.encode(message);

	const signatureBuffer = await subtle.sign(
		{
			name: EC_NAME,
			hash: SHA_DEFAULT,
		},
		key,
		encodedView
	);

 	return new Uint8Array(signatureBuffer);
}

export async function verifySignature(key: CryptoKey, object: unknown, signature: string) {
	assert(key.type === "public");
	assert(key.algorithm.name === EC_NAME);

	const message = JSON.stringify(object);
	const textEncoder = new TextEncoder();
	const messageBuffer = textEncoder.encode(message);
	const signatureBuffer = hexStringtoByteArray(signature);

	const result = await subtle.verify(
		{
			name: EC_NAME,
			hash: SHA_DEFAULT,
		},
		key,
		signatureBuffer,
		messageBuffer
	);

	return result;
}
