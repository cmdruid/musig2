import { Bytes } from '@cmdcode/buff-utils'

export type MusigOptions = Partial<MusigConfig>

export interface MusigConfig {
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
  options : MusigOptions = {}
) : MusigConfig {
  return { ...MUSIG_DEFAULTS, ...options }
}
