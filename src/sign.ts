import { Buff, Bytes }   from '@cmdcode/buff-utils'
import { math }          from '@cmdcode/crypto-utils'
import { compute_s }     from './compute.js'
import { get_vector }    from './pubkey.js'
import { parse_keys }    from './utils.js'
import { MusigSession }  from './schema/index.js'

import * as keys from './keys.js'

// We will have a separate method for deriving nonces from seeds.
// We can pre-calc the pub nonces and give them out for the group R calc.
// We can also pass these seeds into the signer to generate the proper sec nonces.

const buffer = Buff.bytes

export function musign (
  context   : MusigSession,
  secret    : Bytes,
  sec_nonce : Bytes
) : Buff {
  // Unpack the context we will use.
  const { challenge, nonce_vector, R_state }   = context
  const { key_state, key_parity, key_vectors } = context
  // Load secret key into buffer.
  const [ sec, pub ] = keys.get_keypair(secret, true, true)
  // Get the vector for our pubkey.
  const p_v = get_vector(key_vectors, pub).big
  const sk  = math.modN(key_parity * key_state * sec.big)
  const cha = buffer(challenge).big
  const n_v = buffer(nonce_vector).big
  // Parse nonce values into an array.
  const sn  = parse_keys(sec_nonce).map(e => {
    // Negate our nonce values if needed.
    return  R_state * e.big
  })
  // Return partial signature.
  return compute_s(sk, p_v, cha, sn, n_v)
  // NOTE: Add a partial sig verfiy check here.
}
