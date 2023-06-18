import tape from 'tape'
import { math_test }   from './src/math.test.js'
import { stress_test } from './src/stress.test.js'
import { unit_tests }  from './src/unit.test.js'
import { demo_test }   from './src/demo.test.js'

import { 
  generator_test,
  point_test,
  tweak_test
} from './src/point.test.js'

tape('Musig2 testing suite.', t => {
  math_test(t)
  generator_test(t)
  point_test(t)
  tweak_test(t)
  stress_test(t)
  unit_tests(t)
  demo_test(t)
})
