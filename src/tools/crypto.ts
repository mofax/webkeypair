const crypto = globalThis.crypto ? globalThis.crypto : require("node:crypto");

export const subtle = crypto.subtle as SubtleCrypto;

export function byteArraytoHexString(byteArray: Uint8Array) {
	return Array.prototype.map
		.call(byteArray, function (byte) {
			return ("0" + (byte & 0xff).toString(16)).slice(-2);
		})
		.join("");
}

export function hexStringtoByteArray(hexString: string) {
	if (hexString.length % 2 !== 0) {
		throw new Error("Invalid hex string");
	}
	let result: number[] = [];
	for (var i = 0; i < hexString.length; i += 2) {
		const parsed = parseInt(hexString.substr(i, 2), 16);
		result.push(parsed);
	}
	return new Uint8Array(result);
}

export async function sha256Digest(data: Uint8Array) {
	const digest = await subtle.digest("SHA-256", data);
	return new Uint8Array(digest);
}
