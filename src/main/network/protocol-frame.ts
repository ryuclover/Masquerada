export const PROTOCOL_MAGIC = Buffer.from('MQRD', 'ascii')
export const PROTOCOL_VERSION = 1
export const HEADER_LENGTH = 12
export const MAX_FRAME_PAYLOAD_BYTES = 64 * 1024 // 64 KB
export const MAX_DECODER_BUFFER_BYTES = (HEADER_LENGTH + MAX_FRAME_PAYLOAD_BYTES) * 2

export enum ProtocolFrameType {
  HANDSHAKE = 0x01,
  SESSION = 0x02,
  HEARTBEAT = 0x03,
  KEY_EXCHANGE = 0x04
}

export type ProtocolErrorCode =
  | 'PROTOCOL_INVALID_MAGIC'
  | 'PROTOCOL_VERSION_UNSUPPORTED'
  | 'PROTOCOL_FRAME_TYPE_UNSUPPORTED'
  | 'PROTOCOL_FLAGS_UNSUPPORTED'
  | 'PROTOCOL_FRAME_TOO_LARGE'
  | 'PROTOCOL_FRAME_TRUNCATED'
  | 'PROTOCOL_FRAME_INVALID'
  | 'PROTOCOL_DECODER_FAILED'

const ERROR_MESSAGES: Record<ProtocolErrorCode, string> = {
  PROTOCOL_INVALID_MAGIC: 'Os bytes mágicos do frame de protocolo são inválidos.',
  PROTOCOL_VERSION_UNSUPPORTED: 'A versão do protocolo não é suportada.',
  PROTOCOL_FRAME_TYPE_UNSUPPORTED: 'O tipo do frame de protocolo não é suportado.',
  PROTOCOL_FLAGS_UNSUPPORTED: 'Flags de protocolo desconhecidas ou inválidas foram recebidas.',
  PROTOCOL_FRAME_TOO_LARGE: 'O tamanho do payload do frame excede o limite máximo permitido.',
  PROTOCOL_FRAME_TRUNCATED: 'Os dados do frame de protocolo estão incompletos ou truncados.',
  PROTOCOL_FRAME_INVALID: 'A estrutura do frame de protocolo é inválida.',
  PROTOCOL_DECODER_FAILED: 'O decodificador de protocolo foi invalidado após um erro estrutural.'
}

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode

  constructor(code: ProtocolErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'ProtocolError'
    this.code = code
  }
}

export interface ProtocolFrame {
  readonly version: typeof PROTOCOL_VERSION
  readonly type: ProtocolFrameType
  readonly flags: number
  readonly payload: Buffer
}

export interface EncodeFrameOptions {
  readonly type: ProtocolFrameType
  readonly payload?: Buffer
}

export function encodeProtocolFrame(options: EncodeFrameOptions): Buffer {
  assertValidFrameType(options.type)

  const payload = options.payload ?? Buffer.alloc(0)

  if (payload.length > MAX_FRAME_PAYLOAD_BYTES) {
    throw new ProtocolError('PROTOCOL_FRAME_TOO_LARGE')
  }

  const frameBuffer = Buffer.allocUnsafe(HEADER_LENGTH + payload.length)

  // 1. Magic (4 bytes)
  PROTOCOL_MAGIC.copy(frameBuffer, 0, 0, 4)

  // 2. Version (uint8)
  frameBuffer.writeUInt8(PROTOCOL_VERSION, 4)

  // 3. Frame Type (uint8)
  frameBuffer.writeUInt8(options.type, 5)

  // 4. Flags (uint16BE) - estritamente 0 na versão 1
  frameBuffer.writeUInt16BE(0, 6)

  // 5. Payload Length (uint32BE)
  frameBuffer.writeUInt32BE(payload.length, 8)

  // 6. Payload (opaque bytes)
  if (payload.length > 0) {
    payload.copy(frameBuffer, HEADER_LENGTH)
  }

  return frameBuffer
}

export function decodeSingleProtocolFrame(buffer: Buffer): ProtocolFrame {
  if (buffer.length < HEADER_LENGTH) {
    throw new ProtocolError('PROTOCOL_FRAME_TRUNCATED')
  }

  // 1. Magic validation
  if (!buffer.subarray(0, 4).equals(PROTOCOL_MAGIC)) {
    throw new ProtocolError('PROTOCOL_INVALID_MAGIC')
  }

  // 2. Version validation
  const version = buffer.readUInt8(4)
  if (version !== PROTOCOL_VERSION) {
    throw new ProtocolError('PROTOCOL_VERSION_UNSUPPORTED')
  }

  // 3. Type validation
  const frameType = buffer.readUInt8(5)
  assertValidFrameType(frameType)

  // 4. Flags validation (must be strictly 0)
  const flags = buffer.readUInt16BE(6)
  if (flags !== 0) {
    throw new ProtocolError('PROTOCOL_FLAGS_UNSUPPORTED')
  }

  // 5. Payload length validation
  const payloadLength = buffer.readUInt32BE(8)
  if (payloadLength > MAX_FRAME_PAYLOAD_BYTES) {
    throw new ProtocolError('PROTOCOL_FRAME_TOO_LARGE')
  }

  const totalLength = HEADER_LENGTH + payloadLength

  if (buffer.length < totalLength) {
    throw new ProtocolError('PROTOCOL_FRAME_TRUNCATED')
  }

  if (buffer.length > totalLength) {
    throw new ProtocolError('PROTOCOL_FRAME_INVALID')
  }

  const payload = Buffer.from(buffer.subarray(HEADER_LENGTH, totalLength))

  return Object.freeze({
    version: PROTOCOL_VERSION,
    type: frameType,
    flags,
    get payload(): Buffer {
      return Buffer.from(payload)
    }
  })
}

export class ProtocolFrameDecoder {
  private buffer: Buffer = Buffer.alloc(0)
  private invalidated = false

  push(chunk: Buffer): ProtocolFrame[] {
    if (this.invalidated) {
      throw new ProtocolError('PROTOCOL_DECODER_FAILED')
    }

    if (chunk.length === 0) {
      return []
    }

    if (this.buffer.length + chunk.length > MAX_DECODER_BUFFER_BYTES) {
      this.invalidated = true
      throw new ProtocolError('PROTOCOL_FRAME_TOO_LARGE')
    }

    try {
      this.buffer =
        this.buffer.length === 0
          ? Buffer.from(chunk)
          : Buffer.concat([this.buffer, chunk])

      const frames: ProtocolFrame[] = []

      while (this.buffer.length >= HEADER_LENGTH) {
        // Valida Magic
        if (!this.buffer.subarray(0, 4).equals(PROTOCOL_MAGIC)) {
          throw new ProtocolError('PROTOCOL_INVALID_MAGIC')
        }

        // Valida Version
        const version = this.buffer.readUInt8(4)
        if (version !== PROTOCOL_VERSION) {
          throw new ProtocolError('PROTOCOL_VERSION_UNSUPPORTED')
        }

        // Valida Type
        const frameType = this.buffer.readUInt8(5)
        assertValidFrameType(frameType)

        // Valida Flags
        const flags = this.buffer.readUInt16BE(6)
        if (flags !== 0) {
          throw new ProtocolError('PROTOCOL_FLAGS_UNSUPPORTED')
        }

        // Valida Payload Length antes de qualquer alocação
        const payloadLength = this.buffer.readUInt32BE(8)
        if (payloadLength > MAX_FRAME_PAYLOAD_BYTES) {
          throw new ProtocolError('PROTOCOL_FRAME_TOO_LARGE')
        }

        const totalLength = HEADER_LENGTH + payloadLength

        if (this.buffer.length < totalLength) {
          // Frame incompleto no buffer, aguarda mais chunks
          break
        }

        // Extrai o payload de forma isolada
        const payload = Buffer.from(this.buffer.subarray(HEADER_LENGTH, totalLength))
        this.buffer = this.buffer.subarray(totalLength)

        frames.push(
          Object.freeze({
            version: PROTOCOL_VERSION,
            type: frameType,
            flags,
            get payload(): Buffer {
              return Buffer.from(payload)
            }
          })
        )
      }

      return frames
    } catch (error) {
      this.invalidated = true
      if (error instanceof ProtocolError) {
        throw error
      }
      throw new ProtocolError('PROTOCOL_FRAME_INVALID')
    }
  }

  finish(): void {
    if (this.invalidated) {
      throw new ProtocolError('PROTOCOL_DECODER_FAILED')
    }

    if (this.buffer.length > 0) {
      this.invalidated = true
      throw new ProtocolError('PROTOCOL_FRAME_TRUNCATED')
    }
  }

  isInvalidated(): boolean {
    return this.invalidated
  }
}

function assertValidFrameType(
  type: unknown
): asserts type is ProtocolFrameType {
  if (
    typeof type !== 'number' ||
    !Number.isInteger(type) ||
    (type !== ProtocolFrameType.HANDSHAKE &&
      type !== ProtocolFrameType.SESSION &&
      type !== ProtocolFrameType.HEARTBEAT &&
      type !== ProtocolFrameType.KEY_EXCHANGE)
  ) {
    throw new ProtocolError('PROTOCOL_FRAME_TYPE_UNSUPPORTED')
  }
}
