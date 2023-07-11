import {
  Buff  as BuffType,
  Bytes as BytesType
} from '@cmdcode/buff-utils'

export type Buff  = BuffType
export type Bytes = BytesType

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
