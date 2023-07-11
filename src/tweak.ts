import { modN }  from './math.js'
import { Bytes } from './schema/index.js'

import {
  N,
  G,
  Point,
  mod_key,
  is_even,
  point_add,
  point_mul,
  assert_point
} from './point.js'

export type PointData = [
  point  : Point,
  parity : bigint,
  state  : bigint,
  tweak  : bigint
]

export function apply_tweaks (
  point  : Point,
  tweaks : Bytes[]
) : PointData {
  // Convert our tweaks to integers.
  const ints = tweaks.map(e => mod_key(e).big)
  const pos  = BigInt(1)
  const neg  = N - pos

  let Q      = point,
      parity = pos, // Handles negation for current round.
      state  = pos, // Tracks negation state across rounds.
      tweak  = 0n   // Stores the accumulated (negated) tweak.

  for (const t of ints) {
    // If point is odd, g should be negative.
    parity = (!is_even(Q)) ? neg : pos
    // Invert Q based on g, then add tweak.
    Q = point_add(point_mul(Q, parity), point_mul(G, t))
    // Assert that Q is not null.
    assert_point(Q)
    // Store our progress for the next round.
    state = modN(parity * state)
    tweak = modN(t + parity * tweak)
  }
  parity = (!is_even(Q)) ? neg : pos
  return [ Q, parity, state, tweak ]
}
