import { assert } from 'node:console';
import test from 'node:test';
import { generateKeyPair } from './main'

test('parent test', async (t) => {
    await t.test("generates keypair", async () => {
        const keyPair = await generateKeyPair();
        const {publicKey, privateKey} = keyPair;
        assert(publicKey.type === 'public');
        assert(privateKey.type === 'private');
    })
});
