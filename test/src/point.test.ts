import { Buff }  from '@cmdcode/buff-utils'
import { Field, Point } from '@cmdcode/crypto-utils'
import { Test }  from 'tape'
import * as ECC  from '../../src/point.js'
import * as Gen  from '../../src/generate.js'

export function generator_test(t : Test) {
  const a = Buff.random()
  const b = Buff.random()
  const F1 = Gen.generate_seckey(a).hex
  const F2 = new Field(a).hex
  const P1 = Gen.generate_pubkey(b, false).hex
  const P2 = new Field(b).point.hex

  t.test('Testing key generation.', t => {
    t.plan(2)
    t.equal(F1, F2, 'Field number value should be equal.')
    t.equal(P1, P2, 'Point x value should be equal.')
  })
}

export function point_test(t : Test) {
  const a = Gen.generate_pubkey(Buff.random())
  const P1 = ECC.point_x(a, false)
  ECC.assert_point(P1)
  const P2 = ECC.to_bytes(P1, false)
  const P3 = new Point(a)

  const match = ECC.point_eq(P1, { x: P3.x.big, y: P3.y.big })

  const E1 = ECC.is_even(P1)
  const E3 = P3.hasEvenY

  t.test('Testing point conversion.', t => {
    t.plan(4)
    t.equal(P1.x, P3.x.big, 'Point x value should be equal.')
    t.equal(P2.hex, P3.hex, 'Point compressed value should be equal.')
    t.equal(match, true, 'Points should validate as equal.')
    t.equal(E1, E3, 'Points should have equal Y parity.')
  })
}

export function tweak_test(t : Test) {
  const seed  = Buff.random()
  const tweak = Buff.random()
  const P1 = Gen.generate_point(seed)
  const P2 = new Field(seed).point
  const PT = Gen.generate_pubkey(tweak)

  const TP = ECC.point_x(PT)
  const A1 = ECC.point_add(P1, TP)
  const A2 = P2.add(new Point(TP.x, TP.y))

  const M1 = ECC.point_mul(A1, tweak.big)
  const M2 = A2.mul(tweak)
  ECC.assert_point(M1)

  t.test('Testing point math.', t => {
    t.plan(3)
    t.equal(P1.x, P2.x.big, 'Both points x value should be equal.')
    t.equal(A1.x, A2.x.big, 'Added points x value should be equal.')
    t.equal(M1.x, M2.x.big, 'Multiplied x value should be equal.')
  })
}
