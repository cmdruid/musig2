import { Bytes }      from '@cmdcode/buff-utils'
import { PointState } from './schema/index.js'

import {
  assert,
  PointData,
  math,
  point
} from '@cmdcode/crypto-utils'

const { CONST } = math

export function apply_tweaks (
  int_pt : PointData,
  tweaks : Bytes[]
) : PointState {
  // Convert our tweaks to integers.
  const ints = tweaks.map(e => math.mod_bytes(e).big)
  const pos  = BigInt(1)
  const neg  = CONST.N - pos

  let Q : PointData | null = int_pt,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!point.is_even(Q)) ? neg : pos
    // Invert Q based on g, then add tweak.
    Q = point.add(point.mul(Q, parity), point.mul(CONST.G, t))
    // Assert that Q is not null.
    assert.valid_point(Q)
    // Store our progress for the next round.
    state = math.modN(parity * state)
    tweak = math.modN(t + parity * tweak)
  }

  parity = (!point.is_even(Q)) ? neg : pos

  return {
    point      : Q,
    key_parity : parity,
    key_state  : state,
    key_tweak  : tweak
  }
}
