import { Field, Point } from '@cmdcode/crypto-utils'
import { Buff }  from '@cmdcode/buff-utils'
import { Test }  from 'tape'
import * as ECC  from '../../src/point.js'
import * as Gen  from '../../src/generate.js'

type TestResult = [
  label  : string,
  result : boolean
]

const DEBUG = false

export function stress_test(t : Test) {
  t.test('Key creation stress test', t => {
    const rounds  = 10
    const results : TestResult[] = []
    for (let i = 0; i < rounds; i++) {
      const secret = Buff.random()
      const P      = Point.generate(secret)
      const pubkey = Gen.generate_pubkey(secret, false)
      const pointA = { x: P.x.big, y: P.y.big }
      const pointB = ECC.point_x(pubkey)
      const bytesA = ECC.to_bytes(pointA)
      const bytesB = ECC.to_bytes(pointB)

      if (DEBUG) {
        console.log('pubkey:', pubkey.hex)
        console.log('pointA:', Buff.big(pointA.x).hex)
        console.log('pointB:', Buff.big(pointB.x).hex)
        console.log('isevenA:', ECC.is_even(pointA))
        console.log('isevenB:', ECC.is_even(pointB))
        console.log('bytesA:', bytesA.hex)
        console.log('bytesB:', bytesB.hex)
      }
      
      results.push(
        [ 'pubkey === bytesA', (pubkey.hex === bytesA.hex) ],
        [ 'bytesA === bytesB', (bytesA.hex === bytesB.hex) ],
        [ 'pointAx === pointBx', (pointA.x === pointB.x)   ],
        [ 'pointAy === pointBy', (pointA.y === pointB.y)   ],
        [ 'is_equal(A, B)', ECC.point_eq(pointA, pointB)   ],
        [ 
          'is_even(A) === isEven(B)', 
          ECC.is_even(pointA) === ECC.is_even(pointB)
        ]
      )
    }

    const failures = results.filter(e => e[1] === false)

    if (failures.length !==0) {
      console.log('Failure Cases:')
      console.log(failures)
    }

    t.plan(1)
    t.equal(failures.length, 0, 'All tests should pass with zero failures.')
  })

  t.test('Key arithmetic stress test', t => {
    const options = { xonly: false, strict: true }
    const rounds  = 1
    const results : TestResult[] = []

    for (let i = 0; i < rounds; i++) {
      const seed  = Buff.random()
      const tweak = Buff.random()
      const P1 = Gen.generate_point(seed)
      const P2 = new Field(seed).point
      const PT = Gen.generate_pubkey(tweak)

      const TP = ECC.point_x(PT, options.xonly)
      const A1 = ECC.point_add(P1, TP)
      const A2 = P2.add(new Point(TP.x, TP.y))

      const M1 = ECC.point_mul(A1, tweak.big)
      const M2 = A2.mul(tweak)
      ECC.assert_point(M1)

      results.push(
        [ 'P1.x === P2.x', (P1.x === P2.x.big) ],
        [ 'A1.x === A2.x', (A1.x === A2.x.big) ],
        [ 'M1.x === M2.x', (M1.x === M2.x.big) ],
      )
    }

    const failures = results.filter(e => e[1] === false)
    
    if (failures.length !==0) {
      console.log('Failure Cases:')
      console.log(failures)
    }

    t.plan(1)
    t.equal(failures.length, 0, 'All tests should pass with zero failures.')
  })
}
