import { Buff }    from '@cmdcode/buff'
import { schnorr } from '@noble/curves/secp256k1'

import {
  get_ctx,
  keys,
  musign,
  combine_psigs,
  MusigOptions,
  get_key_ctx
} from '../src/index.js'

import { get_pubkey }       from '@cmdcode/crypto-tools/keys'
import { Point }            from '@cmdcode/crypto-tools'
import { gen_seckey }       from '@cmdcode/musig2/keys'
import { add_sig_adaptors } from '@cmdcode/musig2/util'

// Encode an example string as bytes.
const encoder = new TextEncoder()
const message = encoder.encode('Hello world!')

// Create an example list of signers.
const signers = [ 'alice', 'bob', 'carol' ]
// Store each member's wallet in an array.
const wallets : any[] = []

// Create an "adaptor" tweak to include in signing.
const adaptor_sk = gen_seckey()
const adaptor_pk = get_pubkey(adaptor_sk, true)
// Configure the musig options to include the key tweak.
const options : MusigOptions = { adaptor_tweaks : [ adaptor_pk ] }

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

// You can verify the public adaptor tweak by adding it to the un-tweaked group pubkey.
const { group_pubkey } = get_key_ctx(group_keys)
const adaptor_point    = Point.from_x(adaptor_pk)
const tweaked_group_pk = Point.from_x(group_pubkey, true).add(adaptor_point).x

// Both group pubkeys should match. 
console.log('is valid pubkey:', (ctx.group_pubkey.hex === tweaked_group_pk.hex))

// The signature will be invalid without the tweak.
const is_valid_untweaked = schnorr.verify(signature, message, tweaked_group_pk)

// We can add the tweak to the signature to make it valid.
const adapted_sig = add_sig_adaptors(ctx, signature, [ adaptor_sk ])

// Check if the signature is valid using an independent library.
const is_valid_tweaked = schnorr.verify(adapted_sig, message, tweaked_group_pk)

console.log('is valid untweaked :', is_valid_untweaked)
console.log('is valid tweaked   :', is_valid_tweaked)
