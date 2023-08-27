# musig2

A simple and easy-to-use musig2 library, written in typescript.

- Simplified version of the latest musig2 protocol [BIP0327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
- Use four simple methods for an entire signing session: `get_ctx`, `sign`, `combine` and `verify`.
- Supports key tweaking for taproot script paths.
- Includes `keys` util for generates keys and nonce values.

> NOTE: This library is still under development. Expect dragons!  

More documentation coming soon!

## Import

This package is available on NPM for easy import into your nodejs or browser-based project:

```bash
# Node via NPM:
npm install @cmdcode/musig2
# Node via Yarn:
yarn add @cmdcode/musig2
```
Example import as an ES module:
```ts
import * as musig from '@cmdcode/musig2'
```
Example import into a browser-based project:
```html
<script src="https://unpkg.com/@cmdcode/musig2"></script>
<script> const musig = window.musig2 </script>
```

## Basic Usage

Here is a basic example of using Musig2 for signing. The steps are as follows:

 * Each signer must collect the public keys and nonces from other signers.
 * Each signer then creates a partial signature and shares it around.
 * Once all partial signatures are collected, any signer can combine them into the full signature.

Check out [`test/src/demo.test.ts`](test/src/demo.test.ts) for a full reference implementation.

```ts
// Import the package.
import * as musig from '@cmdcode/musig2'

// Encode an example string as bytes.
  const encoder = new TextEncoder()
  const message = encoder.encode('Hello world!')

  // Let's create an example list of signers.
  const signers = [ 'alice', 'bob', 'carol' ]
  // We'll store each member's wallet in an array.
  const wallets : any[] = []
  // Let's also add some additional key tweaks.
  const tweak1  = musig.util.random(32)
  const tweak2  = musig.util.random(32)
  const options = { tweaks : [ tweak1, tweak2 ], commit_tweaks: false }

  // Setup a dummy wallet for each signer.
  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = musig.util.random(32)
    const nonce  = musig.util.random(64)
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = musig.keys.get_keypair(secret)
    // Create a pair of nonces (numbers only used once).
    const [ sec_nonce, pub_nonce ] = musig.keys.get_nonce_pair(nonce)
    // Add the member's wallet to the array.
    wallets.push({
      name, sec_key, pub_key, sec_nonce, pub_nonce
    })
  }

  // Collect public keys and nonces from all signers.
  const group_keys   = wallets.map(e => e.pub_key)
  const group_nonces = wallets.map(e => e.pub_nonce)

  // Combine all your collected keys into a signing session.
  const ctx = musig.ctx.get_ctx(group_keys, group_nonces, message, options)

  // Each member creates their own partial signature,
  // using their own computed signing session.
  const group_sigs = wallets.map(wallet => {
    return musig.sign.with_ctx(
      ctx,
      wallet.sec_key,
      wallet.sec_nonce
    )
  })

  // Combine all the partial signatures into our final signature.
  const signature = musig.combine.psigs(ctx, group_sigs)

  // Check if the signature is valid.
  const isValid1 = musig.verify.with_ctx(ctx, signature)
```

You can also verify the signature using an independent cryptography library, such as the excellent [@noble/curves](https://github.com/paulmillr/noble-curves) library by Paul Miller.

```ts
// BONUS: Check if the signature is valid using an independent library.
import { schnorr } from '@noble/curves/secp256k1'

const isValid2 = schnorr.verify(signature, message, ctx.group_pubkey)
```

## Development / Testing

This library uses `yarn` for package management.

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
