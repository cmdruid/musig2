import { Bytes } from '@cmdcode/buff'

export type MusigOptions = Partial<MusigConfig>

export interface MusigConfig {
  adaptor_tweaks : Bytes[]
  key_tweaks     : Bytes[]
}

export const MUSIG_DEFAULTS = {
  adaptor_tweaks : [],
  key_tweaks     : []
}

export const CONST = {
  SAFE_MIN_VALUE: 0xFFn ** 16n
}

export function musig_config (
  options : MusigOptions = {}
) : MusigConfig {
  return { ...MUSIG_DEFAULTS, ...options }
}
