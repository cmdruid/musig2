# musig2

A simple and easy-to-use musig2 library, written in typescript.

- Generates keys and nonce values for a group signing session.
- Uses `sign`, `combine` and `verify` to create and validate signatures.
- Simplified version of the latest musig2 protocol [BIP0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
- Supports key tweaking for taproot script paths.

> NOTE: This library is still under heavy development. Expect dragons!  

More documentation coming soon!

## Import

This package is available on NPM for easy import:

```bash
# Using NPM
npm install @cmdcode/musig2
# Using Yarn
yarn add @cmdcode/musig2
```

## Basic Usage

Here is a basic example of using Musig2 for signing. The steps are as follows:

 * Each signer must collect the public keys and nonces from other signers.
 * Each signer then creates a session and partial signature.
 * Once all partial signatures are collected, any signer can combine them into the final signature.

Check out [`test/src/demo.test.ts`](test/src/demo.test.ts) for a full reference implementation.

```ts
// Import the package.
import * as Musig2 from '@cmdcode/musig2'

// Encode an example string as bytes.
const encoder = new TextEncoder()
const message = encoder.encode('Hello world!')

// Let's create an example list of signers.
const signers = [ 'alice', 'bob', 'carol' ]
// We'll store each member's wallet in an array.
const wallets : any[] = []
// Let's also add some additional key tweaks.
const tweak1  = Musig2.gen.random()
const tweak2  = Musig2.gen.random()
const options = { tweaks : [ tweak1, tweak2 ] }

// Setup a dummy wallet for each signer.
for (const name of signers) {
  // Generate some random secrets using WebCrypto.
  const secret = Musig2.gen.random(32)
  const nonce  = Musig2.gen.random(64)
  // Create a pair of signing keys.
  const [ sec_key, pub_key     ] = Musig2.gen.key_pair(secret)
  // Create a pair of nonces (numbers only used once).
  const [ sec_nonce, pub_nonce ] = Musig2.gen.nonce_pair(nonce)
  // Add the member's wallet to the array.
  wallets.push({
    name, sec_key, pub_key, sec_nonce, pub_nonce
  })
}

// Collect public keys and nonces from all signers.
const group_keys   = wallets.map(e => e.pub_key)
const group_nonces = wallets.map(e => e.pub_nonce)

// Combine all your collected keys into a signing session.
const session = Musig2.combine.keys(group_keys, group_nonces, message, options)

// Each member creates their own partial signature,
// using their own computed signing session.
const group_sigs = wallets.map(wallet => {
  return Musig2.sign(
    session,
    wallet.sec_key,
    wallet.sec_nonce
  )
})

// Combine all the partial signatures into our final signature.
const signature = Musig2.combine.sigs(session, group_sigs)

// Check if the signature is valid.
const isValid = Musig2.verify.sig (
  session,
  signature
)
```

## Development / Testing

This library uses `yarn` for package management and `vite` for a development / demo server.

```bash
## Clean up any old builds.
yarn clean
## Run all tests in the suite.
yarn test
## Build a new release.
yarn release
```

## Bugs / Issues

If you run into any bugs or have any questions, please submit an issue ticket.

## Contribution

Feel free to fork and make contributions. Suggestions are welcome!

## License

Use this library however you want!

## Contact

You can find me on nostr at: `npub1gg5uy8cpqx4u8wj9yvlpwm5ht757vudmrzn8y27lwunt5f2ytlusklulq3`
