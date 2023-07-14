import { Test }    from 'tape'
import { Bytes }   from '@cmdcode/buff-utils'
import { schnorr } from '@noble/curves/secp256k1'
import * as Musig2 from '../../src/index.js'

export function ecdh_test (t : Test) {
  // Encode an example string as bytes.
  const encoder = new TextEncoder()
  const message = encoder.encode('Hello world!')

  // Let's create an example list of signers.
  const signers = [ 'alice', 'bob' ]
  // We'll store each member's wallet in an array.
  const wallets : any[] = []
  // Let's also add some additional key tweaks.
  const tweak1  = Musig2.gen.seckey()
  const tweak2  = Musig2.gen.seckey()
  const options = { tweaks : [ tweak1, tweak2 ], commit_tweaks: false }

  // Setup a dummy wallet for each signer.
  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = Musig2.util.random(32)
    const nonce  = Musig2.util.random(32)
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = Musig2.ecc.get_keypair(secret, true)
    // Create a pair of nonce keys.
    const [ sec_nonce, pub_nonce ] = Musig2.ecc.get_keypair(nonce, false, false)
    // Add the member's wallet to the array.
    wallets.push({
      name, sec_key, pub_key, sec_nonce, pub_nonce
    })
  }

  // Get wallets for each signer.
  const a_wallet = wallets.find(e => e.name === 'alice')
  const b_wallet = wallets.find(e => e.name === 'bob')

  // Collect public keys from all signers.
  const group_keys = wallets.map(e => e.pub_key)

  // Alice derives a deterministic signing session.
  const [ session, a_secnonce ] = Musig2.ctx.get_shared (
    group_keys, 
    a_wallet.sec_nonce,
    b_wallet.pub_nonce,
    message, 
    options
  )

  // Bob derives the same deterministic signing session.
  const [ _, b_secnonce ] = Musig2.ctx.get_shared (
    group_keys,
    b_wallet.sec_nonce,
    a_wallet.pub_nonce,
    message,
    options
  )

  // Store the signatures for each member.
  const group_sigs : Bytes[] = []

  group_sigs.push(
    // Alice signs with her sec_nonce.
    Musig2.musign (
      session,
      a_wallet.sec_key,
      a_secnonce
    )
  )

  group_sigs.push(
    // Bob signs with his sec_nonce.
    Musig2.musign (
      session,
      b_wallet.sec_key,
      b_secnonce
    )
  )

  // Combine all the partial signatures into our final signature.
  const signature = Musig2.calc.signature(session, group_sigs)

  // Check if the signature is valid.
  const isValid1 = Musig2.verify.musig (session, signature)

  // BONUS: Check if the signature is valid using an independent library.
  const { group_pubkey } = session
  const pubkey   = group_pubkey.slice(1)
  const isValid2 = schnorr.verify(signature, message, pubkey)

  t.test('Testing deterministic signing demo.', t => {
    t.plan(2)
    t.true(isValid1, 'The test demo should produce a valid signature.')
    t.true(isValid2, 'The signature should validate using another library.')
  })
}

