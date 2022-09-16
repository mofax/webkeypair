## WebKeypair

Uses subtle crypto to generate an ECDSA keypair. Works in NodeJS > 18 and modern browsers.

> Also generates an address inspired by ethereum addresses

Example

```json
{
	"address": "0xx1970252dcdd6509f90b0a9791f074cee503053c74",
	"keyPair": {
		"privateKey": {
			"key_ops": ["sign"],
			"ext": true,
			"kty": "EC",
			"x": "OFD32RPiUgdlS9dO-yq9d9c5ncUkPHWJQwEjydRvafU",
			"y": "9sTj2BLQzsqLvSN84B60W-cPSdxIQG7jzrdRvw6VhMU",
			"crv": "P-256",
			"d": "9hpaQKoKGwpa50Bhu8bYdkkOpZIU0iaXP8nbKVhvnRU"
		},
		"publicKey": {
			"key_ops": ["verify"],
			"ext": true,
			"kty": "EC",
			"x": "OFD32RPiUgdlS9dO-yq9d9c5ncUkPHWJQwEjydRvafU",
			"y": "9sTj2BLQzsqLvSN84B60W-cPSdxIQG7jzrdRvw6VhMU",
			"crv": "P-256"
		}
	}
}
```
