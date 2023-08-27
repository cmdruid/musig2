import { Test }    from 'tape'
import { schnorr } from '@noble/curves/secp256k1'
import * as musig  from '../../src/index.js'

export default function (t : Test) {

  // Encode an example string as bytes.
  const encoder = new TextEncoder()
  const message = encoder.encode('Hello world!')

  // Let's create an example list of signers.
  const signers = [ 'alice', 'bob', 'carol' ]
  // We'll store each member's wallet in an array.
  const wallets : any[] = []
  // Let's also add some additional key tweaks.
  const tweak1   = musig.util.random(32)
  const tweak2   = musig.util.random(32)
  const options  = {
    key_tweaks : [ tweak1, tweak2 ]
  }

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

  // BONUS: Check if the signature is valid using an independent library.
  const { group_pubkey } = ctx
  const isValid2 = schnorr.verify(signature, message, group_pubkey)

  t.test('Testing example demo.', t => {
    t.plan(2)
    t.true(isValid1, 'The test demo should produce a valid signature.')
    t.true(isValid2, 'The signature should validate using another library.')
  })
}
