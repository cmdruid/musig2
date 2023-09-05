import { Test }    from 'tape'
import { Buff }    from '@cmdcode/buff-utils'
import { schnorr } from '@noble/curves/secp256k1'

import {
  combine,
  create_ctx,
  get_key_ctx,
  get_nonce_ctx,
  keys,
  musign,
  MusigOptions,
  util,
  verify_musig
}  from '../../src/index.js'

export default function (t : Test) {
  // Store all signature results here.
  const sig_results  : boolean[] = []

  // Let's create a list of messages.
  const messages = [
    'Today it is sunny!',
    'Today it is cloudy!',
    'Today it is raining!'
  ]

  // Let's create an example list of signers.
  const signers = [ 'alice', 'bob', 'carol' ]
  // We'll store each member's wallet in an array.
  const wallets : any[] = []
  // Let's also add some additional key tweaks.
  const tweak1   = util.random(32)
  const tweak2   = util.random(32)
  const options  : MusigOptions = {
    key_tweaks : [ tweak1, tweak2 ]
  }

  // Setup a dummy wallet for each signer.
  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = util.random(32)
    const nonce  = util.random(64)
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = keys.get_keypair(secret)
    // Create a pair of nonces (numbers only used once).
    const [ sec_nonce, pub_nonce ] = keys.get_nonce_pair(nonce)
    // Add the member's wallet to the array.
    wallets.push({
      name, sec_key, pub_key, sec_nonce, pub_nonce
    })
  }

  // Collect public keys and nonces from all signers.
  const group_keys   = wallets.map(e => e.pub_key)
  const group_nonces = wallets.map(e => e.pub_nonce)

  // Our key context will not change between sign sessions.
  const key_ctx = get_key_ctx(group_keys, options)

  // For each message to be signed:
  for (const message of messages) {
    // Compute a message hash to be signed.
    const msg = Buff.str(message).digest
    // We will tweak our nonces by the message hash.
    options.nonce_tweaks = [ msg ]
    // Compute the nonce context with the added tweak.
    const nonce_ctx = get_nonce_ctx (
      group_nonces,
      key_ctx.group_pubkey,
      msg
    )
    // Combine our key and nonce contexts into a full context object.
    const ctx = create_ctx(key_ctx, nonce_ctx, options)
    // Each member then creates their own partial signature.
    const group_psigs = wallets.map(wallet => {
      return musign (
        ctx,
        wallet.sec_key,
        wallet.sec_nonce
      )
    })

    // Combine all the partial signatures into our final signature.
    const signature = combine.psigs(ctx, group_psigs)

    // Check if the signature is valid.
    sig_results.push(verify_musig(ctx, signature))

    // BONUS: Check if the signature is valid using an independent library.
    const { group_pubkey } = ctx
    sig_results.push(schnorr.verify(signature, msg, group_pubkey))
  }
  
  // Count how many signatures failed (if any).
  const failures = sig_results.filter(e => !e)

  t.test('Adaptor signing demo.', t => {
    t.plan(1)
    t.true(failures.length === 0, 'All signatures should pass verification')
  })
}
