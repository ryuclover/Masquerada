import { Duplex } from 'node:stream'

const TRANSPORT_STREAM_TOKEN = Symbol('MasqueradaTransportStream')
const transportStreams = new WeakSet<object>()

export interface CreateMasqueradaTransportStreamOptions {
  readonly maxQueuedBytes: number
  readonly onWrite: (bytes: Buffer) => Promise<void>
  readonly onLocalClose: () => void
}

/** A bounded byte-stream transport used by the existing MQRD client/server pipelines. */
export class MasqueradaTransportStream extends Duplex {
  constructor(
    token: symbol,
    private readonly onTransportWrite: (bytes: Buffer) => Promise<void>,
    private readonly onTransportClose: () => void,
    maxQueuedBytes: number
  ) {
    if (token !== TRANSPORT_STREAM_TOKEN || !Number.isInteger(maxQueuedBytes) || maxQueuedBytes < 1) {
      throw new Error('TRANSPORT_STREAM_INVALID')
    }
    super({ readableHighWaterMark: maxQueuedBytes, writableHighWaterMark: maxQueuedBytes })
    transportStreams.add(this)
    this.on('error', () => {})
  }

  _read(): void {}

  _write(chunk: Buffer | string, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    const bytes = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, encoding)
    void this.onTransportWrite(bytes).then(() => callback(), (cause: unknown) => {
      callback(cause instanceof Error ? cause : new Error('TRANSPORT_STREAM_WRITE_FAILED'))
    })
  }

  _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    try {
      this.onTransportClose()
    } finally {
      callback(error)
    }
  }
}

export interface MasqueradaTransportStreamHandle {
  readonly stream: MasqueradaTransportStream
  readonly deliver: (bytes: Buffer) => boolean
  readonly remoteClose: () => void
}

/** Internal transport adapter factory. Returned stream is runtime branded; literals are rejected. */
export function createMasqueradaTransportStream(
  options: CreateMasqueradaTransportStreamOptions
): MasqueradaTransportStreamHandle {
  let remotelyClosed = false
  const stream = new MasqueradaTransportStream(
    TRANSPORT_STREAM_TOKEN,
    options.onWrite,
    options.onLocalClose,
    options.maxQueuedBytes
  )
  return Object.freeze({
    stream,
    deliver(bytes: Buffer): boolean {
      if (remotelyClosed || stream.destroyed || !Buffer.isBuffer(bytes)) return false
      return stream.push(Buffer.from(bytes))
    },
    remoteClose(): void {
      if (remotelyClosed) return
      remotelyClosed = true
      stream.push(null)
    }
  })
}

export function isMasqueradaTransportStream(value: unknown): value is MasqueradaTransportStream {
  return typeof value === 'object' && value !== null && transportStreams.has(value)
}
