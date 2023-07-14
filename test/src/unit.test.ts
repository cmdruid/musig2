import { Buff } from '@cmdcode/buff-utils'
import { Test } from 'tape'

import { to_bytes }    from '../../src/ecc/point.js'
import { get_context } from '../../src/context.js'

import {
  get_key_vector,
  combine_pubkeys
} from '../../src/pubkey.js'

import { 
  combine_nonces,
  get_nonce_coeff
} from '../../src/nonce.js'

import {
  compute_R,
  get_challenge,
} from '../../src/compute.js'

import {
  combine_sigs,
  verify_sig
} from '../../src/verify.js'

import vectors from './vectors.json' assert { type : 'json' }
import { musign } from '../../src/sign.js'

type Vector = typeof vectors[0]

export function unit_tests (t : Test) {
  t.comment('Performing unit tests.')

  const count = vectors.length

  for (let i = 0; i < count; i++) {
    const v = vectors[i]
    t.test(`Test vector ${i}:`, t => {
      key_coeff_test(t, v)
      combine_keys_test(t, v)
      combine_nonces_test(t, v)
      nonce_coeff_test(t, v)
      compute_R_test(t, v)
      compute_challenge_test(t, v)
      sign_test(t, v)
      combine_sigs_test(t, v)
      verify_sig_test(t, v)
    })
  }
}

function key_coeff_test (t : Test, v : Vector) {
  const { pub_keys, key_coeffs } = v.group
  const count = pub_keys.length
  t.test('key_coeff_test', t => {
    t.plan(count)
    for (let i = 0; i < count; i++) {
      const ret = get_key_vector(pub_keys, pub_keys[i])
      t.equal(ret.hex, key_coeffs[i], 'Key coefficient hash should match.')
    }
  })
}

function combine_keys_test (t : Test, v : Vector) {
  const { group, group_key, opt } = v
  const [ P ] = combine_pubkeys(group.pub_keys)
  const ret = to_bytes(P)
  t.test('combine_pubkeys_test', t => {
    t.plan(1)
    t.equal(ret.hex, group_key, 'Group pubkey should equal target.')
  })
}

function combine_nonces_test (t : Test, v : Vector) {
  const { group, group_nonce } = v
  const ret = combine_nonces(group.pub_nonces)
  t.test('combine_nonces_test', t => {
    t.plan(1)
    t.equal(ret.hex, group_nonce, 'Group nonce should equal target.')
  })
}

function nonce_coeff_test (t : Test, v : Vector) {
  const { group_nonce, group_key, chall_mesg, nonce_coeff } = v
  const ret = get_nonce_coeff(group_nonce, group_key, chall_mesg)
  t.test('nonce_coeff_test', t => {
    t.plan(1)
    t.equal(ret.hex, nonce_coeff, 'Nonce coefficient hash should match.')
  })
}

function compute_R_test (t : Test, v : Vector) {
  const { group_nonce, nonce_coeff, group_R } = v
  const R = compute_R(group_nonce, nonce_coeff)
  const ret = to_bytes(R)
  t.test('compute_R_test', t => {
    t.plan(1)
    t.equal(ret.slice(1).hex, group_R, 'R.x value hex should match.')
  })
}

function compute_challenge_test (t : Test, v : Vector) {
  const { group_R, group_key, chall_mesg, chall_hash } = v
  const ret = get_challenge(group_R, group_key, chall_mesg)

  t.test('compute_challenge_test', t => {
    t.plan(1)
    t.equal(ret.hex, chall_hash, 'Challenge hash should match.')
  })
}

function sign_test (t : Test, v : Vector) {
  const { group, chall_mesg, opt } = v
  const { pub_keys, pub_nonces, sec_nonces, sec_keys, signatures } = group
  const rounds = group.pub_keys.length

  const session = get_context(pub_keys, pub_nonces, chall_mesg, opt)

  t.test('sign_test', t => {
    t.plan(rounds)
    for (let i = 0; i < rounds; i++) {
      const target = signatures[i]
      const sig = musign (
        session,
        sec_keys[i],
        sec_nonces[i]
      )
      t.equal(sig.hex, target, `Signatures for member ${i+1} should match.`)
    }
  })
}

function combine_sigs_test (t : Test, v : Vector) {
  const { group, group_sig, group_R, chall_mesg, opt } = v
  const { pub_keys, pub_nonces, sec_nonces, sec_keys, signatures } = group
  const session = get_context(pub_keys, pub_nonces, chall_mesg, opt)
  const ret = combine_sigs(session, group.signatures)
  t.test('combine_s_test', t => {
    t.plan(1)
    t.equal(ret.slice(32, 64).hex, group_sig, 'Combined s values should match.')
  })
}

function verify_sig_test (t : Test, v : Vector) {
  const { group, group_sig, group_R, chall_mesg, opt } = v
  const { pub_keys, pub_nonces, } = group
  const session = get_context(pub_keys, pub_nonces, chall_mesg, opt)
  const isValid = verify_sig(session, Buff.join([ group_R, group_sig ]))
  t.test('verify_sig_test', t => {
    t.plan(1)
    t.equal(isValid, true, 'Combined signature values should be valid.')
  })
}
