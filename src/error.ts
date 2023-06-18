interface ErrorReport {
  type   ?: string
  data   ?: string[]
  pubkey ?: string
  reason  : string
}

export class KeyOperationError extends Error {
  type   ?: string
  data   ?: string[]
  pubkey ?: string

  constructor (report : ErrorReport) {
    const { reason = 'Key operation failed!' } = report
    super(reason)
    this.name   = 'KeyOperationError'
    this.pubkey = report.pubkey
    this.type   = report.type
    this.data   = report.data ?? []
  }
}
