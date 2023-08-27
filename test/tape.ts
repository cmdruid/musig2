import tape from 'tape'

import unit_tests from './src/unit.test.js'
import demo_test  from './src/demo.test.js'
import tweak_test from './src/tweak.test.js'

tape('Musig2 testing suite.', t => {
  unit_tests(t)
  demo_test(t)
  tweak_test(t)
})
