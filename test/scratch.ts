import { Bytes }   from '@cmdcode/buff-utils'
import { schnorr } from '@noble/curves/secp256k1'
import * as Musig2 from '../src/index.js'
import { hexify } from '../src/utils.js'

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
  // Create a pair of nonces (numbers only used once).
  const [ sec_nonce, pub_nonce ] = Musig2.ecc.get_keypair(nonce, false, false)
  // Add the member's wallet to the array.
  wallets.push({
    name, sec_key, pub_key, sec_nonce, pub_nonce
  })
}

// Get wallets
const a_wallet = wallets.find(e => e.name === 'alice')
const b_wallet = wallets.find(e => e.name === 'bob')

// Collect public keys and nonces from all signers.
const group_keys = wallets.map(e => e.pub_key)

const a_sess = Musig2.calc.shared_nonce(a_wallet.sec_nonce, b_wallet.pub_nonce, message)
const b_sess = Musig2.calc.shared_nonce(b_wallet.sec_nonce, a_wallet.pub_nonce, message)

console.log(hexify(a_sess))
console.log(hexify(b_sess))

// Combine all your collected keys into a signing session.
const [ a_session, a_secnonce ] = Musig2.ctx.get_shared (
  group_keys, 
  a_wallet.sec_nonce,
  b_wallet.pub_nonce,
  message, 
  options
)

const [ b_session, b_secnonce ] = Musig2.ctx.get_shared (
  group_keys,
  b_wallet.sec_nonce,
  a_wallet.pub_nonce,
  message,
  options
)

console.log(a_session.to_hex())
console.log(b_session.to_hex())

const group_sigs : Bytes[] = []

group_sigs.push(
  Musig2.musign (
    a_session,
    a_wallet.sec_key,
    a_secnonce
  )
)

group_sigs.push(
  Musig2.musign (
    a_session,
    b_wallet.sec_key,
    b_secnonce
  )
)

// Combine all the partial signatures into our final signature.
const signature = Musig2.calc.signature(a_session, group_sigs)

// Check if the signature is valid.
const isValid1 = Musig2.verify.musig (
  b_session,
  signature
)

// BONUS: Check if the signature is valid using an independent library.
const { group_pubkey } = a_session
const pubkey   = group_pubkey.slice(1)
const isValid2 = schnorr.verify(signature, message, pubkey)

console.log('isValid1:', isValid1)
console.log('isValid2:', isValid2)
