import { Test }    from 'tape'
import { Buff }    from '@cmdcode/buff-utils'
import * as Musig2 from '../../src/index.js'

const VERBOSE = true

export function demo_test (t : Test) {

  // Encode an example string as bytes.
  const encoder = new TextEncoder()
  const message = encoder.encode('Hello world!')

  // Let's create an example list of signers.
  const signers = [ 'alice', 'bob', 'carol' ]
  // We'll store each member's wallet in an array.
  const wallets : any[] = []
  // Let's also add an additional key tweak.
  const tweak   = Musig2.util.hash_str('Tweak me!')
  // We can configure our signing session with an options object.
  const options = { tweaks : [] }
  // EDIT: Tweaks are currently broken. :-(

  // Setup a dummy wallet for each signer.
  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = Musig2.gen.random(32)  //Buff.str(name).digest
    const nonce  = Musig2.gen.random(64) //Buff.join([ secret.digest, secret.digest.digest ])
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = Musig2.gen.key_pair(secret)
    // Create a pair of nonces (numbers only used once).
    const [ sec_nonce, pub_nonce ] = Musig2.gen.nonce_pair(nonce)
    // Add the member's wallet to the array.
    wallets.push({
      name, secret, sec_key, pub_key, sec_nonce, pub_nonce
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
      wallet.secret,
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

  t.test('Testing example demo.', t => {
    t.plan(1)
    t.true(isValid, 'The test demo should produce a valid signature.')
  })
}