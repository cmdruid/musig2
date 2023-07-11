import { Bytes } from './types.js'

export type MusigConfig = Partial<MusigOptions>

export interface MusigOptions {
  seeds  : Bytes[]
  tweaks : Bytes[]
}

export const DEFAULT_OPTIONS = {
  seeds  : [],
  tweaks : []
}

export function apply_defaults (
  config : MusigConfig = {}
) : MusigOptions {
  return { ...DEFAULT_OPTIONS, ...config }
}
