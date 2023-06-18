import { Bytes } from '@cmdcode/buff-utils'

interface Return<T> {
  ok   : true
  data : T
}

interface Fail<T> {
  ok   : false
  data : T
  err  : string
}

interface Warn<T> extends Return<T> {
  warn : T
  err  : string
}

export type OpReturn<T = string> = Return<T> | Fail<T> | Warn<T>

export interface MusigOptions {
  strict  : boolean
  tweaks ?: Bytes[]
}
