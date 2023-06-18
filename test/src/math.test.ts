import { Buff }  from '@cmdcode/buff-utils'
import { Field } from '@cmdcode/crypto-utils'
import { Test }  from 'tape'
import * as Math from '../../src/math.js'

export function math_test(t : Test) {
  const a = Buff.random()
  const b = Buff.random()
  const A1 = Math.mod(a.big, b.big)
  const A2 = Field.mod(a.big, b.big)
  const B1 = Math.pow(a.big, b.big)
  const B2 = Field.pow(a.big, b.big)

  t.test('Testing math primitives', t => {
    t.plan(2)
    t.equal(A1, A2, 'Mod operations should be equal.')
    t.equal(B1, B2, 'Pow operations should be equal.')
  })
}
