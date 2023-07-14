import { Bytes } from '@cmdcode/buff-utils'

export type MusigConfig = Partial<MusigOptions>

export interface MusigOptions {
  seeds  : Bytes[]
  tweaks : Bytes[]
}

export const MUSIG_DEFAULTS = {
  seeds  : [],
  tweaks : []
}

export const CONST = {
  SAFE_MIN_VALUE: 0xFFn ** 16n
}

export function musig_config (
  config : MusigConfig = {}
) : MusigOptions {
  return { ...MUSIG_DEFAULTS, ...config }
}
