import { Buff }    from '@cmdcode/buff'
import { schnorr } from '@noble/curves/secp256k1'
import { Test }    from 'tape'

import {
  get_ctx,
  keys,
  musign,
  combine_psigs,
  MusigOptions,
  verify_adapter_sig,
  add_sig_adapters
} from '../../src/index.js'

import { get_pubkey } from '@cmdcode/crypto-tools/keys'
import { gen_seckey } from '@cmdcode/musig2/keys'

export default function (t : Test) {

  // Encode an example string as bytes.
  const encoder = new TextEncoder()
  const message = encoder.encode('Hello world!')

  // Create an example list of signers.
  const signers = [ 'alice', 'bob', 'carol' ]
  // Store each member's wallet in an array.
  const wallets : any[] = []

  // Create an "adaptor" tweak to include in signing.
  const adaptor_sks = [ gen_seckey(), gen_seckey() ]
  const adapter_pks = adaptor_sks.map(e => get_pubkey(e, true))
  // Configure the musig options to include the key tweak.
  const options : MusigOptions = { nonce_tweaks : adapter_pks }

  // Setup a dummy wallet for each signer.
  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = Buff.random(32)
    const nonce  = Buff.random(64)
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = keys.get_keypair(secret)
    // Create a pair of nonces (numbers only used once).
    const [ sec_nonce, pub_nonce ] = keys.get_nonce_pair(nonce)
    // Add the member's wallet to the array.
    wallets.push({ name, sec_key, pub_key, sec_nonce, pub_nonce })
  }

  // Collect public keys and nonces from all signers.
  const group_keys   = wallets.map(e => e.pub_key)
  const group_nonces = wallets.map(e => e.pub_nonce)

  // Create a musig signing context.
  const ctx = get_ctx(group_keys, group_nonces, message, options)

  // Each member signs with the context.
  const group_sigs = wallets.map(wallet => {
    return musign(
      ctx,
      wallet.sec_key,
      wallet.sec_nonce
    )
  })

  // Combine all the partial signatures.
  const signature = combine_psigs(ctx, group_sigs)

  // Check the un-tweaked signature is valid.
  const is_valid_untweaked = verify_adapter_sig(ctx, signature, adapter_pks)

  // We can add the tweak to the signature to make it valid.
  const adapted_sig = add_sig_adapters(ctx, signature, adaptor_sks)

  // Check if the signature is valid using an independent library.
  const is_valid_tweaked = schnorr.verify(adapted_sig, message, ctx.group_pubkey)

  t.test('Testing DLC demo.', t => {
    t.plan(2)
    t.true(is_valid_untweaked, 'The un-tweaked signature should be valid.')
    t.true(is_valid_tweaked,   'The tweaked signature should validate using another library.')
  })
}
