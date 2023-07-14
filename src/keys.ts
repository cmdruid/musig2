import { Buff, Bytes } from '@cmdcode/buff-utils'
import { ecc, sha512 } from '@cmdcode/crypto-utils'

import * as assert from './assert.js'
import * as util   from './utils.js'

export const parse_x     = ecc.parse_x
export const gen_seckey  = ecc.gen_seckey
export const get_seckey  = ecc.get_seckey
export const gen_keypair = ecc.gen_keypair

export const get_pubkey  = (
  seckey  : Bytes,
  xonly  ?: boolean
) : Buff => {
  return ecc.get_pubkey(seckey, xonly)
}

export const get_keypair = (
  secret  : Bytes,
  xonly  ?: boolean,
  even_y ?: boolean
) : Buff[] => {
  return ecc.get_keypair(secret, xonly, even_y)
}

export function get_sec_nonce (
  secret  : Bytes,
  even_y ?: boolean
) : Buff {
  const seed = (secret !== undefined)
    ? sha512(secret)
    : Buff.random(64)
  assert.size(seed, 64)
  const nonces = util
    .parse_keys(seed)
    .map(e => get_seckey(e, even_y))
  return Buff.join(nonces)
}

export function get_pub_nonce (
  sec_nonce : Bytes,
  xonly    ?: boolean
) : Buff {
  const nonces = util
    .parse_keys(sec_nonce)
    .map(e => get_pubkey(e, xonly))
  return Buff.join(nonces)
}

export function get_nonce_pair (
  secret  : Bytes,
  xonly  ?: boolean,
  even_y ?: boolean
) : Buff[]  {
  const sec_nonce = get_sec_nonce(secret, even_y)
  const pub_nonce = get_pub_nonce(sec_nonce, xonly)
  return [ sec_nonce, pub_nonce ]
}

export function gen_nonce_pair (
  xonly  ?: boolean,
  even_y ?: boolean
) : Buff[] {
  const seed = util.random(64)
  return get_nonce_pair(seed, xonly, even_y)
}
