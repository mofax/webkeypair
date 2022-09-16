import assert from "node:assert";
import test from "node:test";
import {
	byteArraytoHexString,
	hexStringtoByteArray,
	sha256Digest,
} from "./crypto";

test("tools/crypto", async (t) => {
	await t.test("byteArraytoHexString", async () => {
		const result = byteArraytoHexString(
			new Uint8Array([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				0x0c, 0x0d, 0x0e, 0x0f,
			])
		);

		assert(
			result === "000102030405060708090a0b0c0d0e0f",
			new Error(`Expected "000102030405060708090a0b0c0d0e0f", got "${result}"`)
		);
	});

	await t.test("hexStringtoByteArray", async () => {
		const result = hexStringtoByteArray("000102030405060708090a0b0c0d0e0f");

		const expectedResult = new Uint8Array([
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f,
		]);

		result.forEach((value, index) => {
			assert(
				value === expectedResult[index],
				new Error(`Expected ${expectedResult[index]}, got ${value}`)
			);
		});
	});

	await t.test("sha256Digest", async () => {
		const result = await sha256Digest(
			new Uint8Array([
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				0x0c, 0x0d, 0x0e, 0x0f,
			])
		);

		// assert sha256 length
		assert(
			result.length === 32,
			new Error(`Expected hash length to be 32, got ${result.length}`)
		);

		const expectedResult = new Uint8Array([
			190, 69, 203, 38, 5, 191, 54, 190, 189, 230, 132, 132, 26, 40, 240, 253,
			67, 198, 152, 80, 163, 220, 229, 254, 219, 166, 153, 40, 238, 58, 137,
			145,
		]);

		result.forEach((value, index) => {
			assert(
				value === expectedResult[index],
				new Error(`Expected ${expectedResult[index]}, got ${value}`)
			);
		});
	});
});
