import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type KeyObject
} from 'node:crypto'
import { isIP } from 'node:net'

import {
  classifyNetworkAddress
} from './network-interfaces'
import { assertValidPort } from './tcp-transport'
import {
  isLegitimateActiveServerHandle,
  type BoundTcpEndpoint,
  type DirectTcpEndpoint,
  type LanTcpServerHandle
} from './lan-transport'
import {
  isLegitimateActivePortMapping,
  MIN_MAPPING_REMAINING_FOR_DESCRIPTOR_SECONDS,
  type ActivePortMappingSource
} from './active-port-mapping'
import {
  isLegitimateActiveDirectGlobalListener,
  type ActiveDirectGlobalListener
} from './direct-global-transport'

export const CONNECTIVITY_DESCRIPTOR_DOMAIN = 'Masquerada/connectivity-descriptor/v1'
export const CONNECTIVITY_DESCRIPTOR_VERSION = 1
export const MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS = 300 // 5 minutos máximo
export const DEFAULT_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS = 180 // 3 minutos default
export const MAX_CONNECTIVITY_CANDIDATES = 16
export const MAX_CONNECTIVITY_DESCRIPTOR_BYTES = 8192 // 8 KB
export const DESCRIPTOR_ID_BYTES = 32
export const ED25519_SIGNATURE_BYTES = 64

export enum ConnectivityCandidateType {
  LAN_TCP = 1,
  PORT_MAPPED_TCP = 2,
  DIRECT_GLOBAL_TCP = 3
}

export type CandidateScope = 'LAN_PRIVATE' | 'LINK_LOCAL' | 'LOOPBACK'

export interface LanTcpCandidate {
  readonly candidateType: ConnectivityCandidateType.LAN_TCP
  readonly family: 4 | 6
  readonly address: string
  readonly port: number
  readonly scope: CandidateScope
}

export interface PortMappedTcpCandidate {
  readonly candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP
  readonly family: 4 | 6
  readonly address: string
  readonly port: number
}

export interface DirectGlobalTcpCandidate {
  readonly candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP
  readonly family: 6
  readonly address: string
  readonly port: number
}

export type ConnectivityCandidate =
  | LanTcpCandidate
  | PortMappedTcpCandidate
  | DirectGlobalTcpCandidate

export interface VerifiedConnectivityDescriptor {
  readonly version: 1
  readonly type: 'connectivity-descriptor'
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly descriptorId: Buffer
  readonly issuedAt: number
  readonly expiresAt: number
  readonly candidates: readonly ConnectivityCandidate[]
  readonly signature: Buffer
  readonly rawEncoded: Buffer
}

export type ConnectivityDescriptorErrorCode =
  | 'DESCRIPTOR_INVALID_SIZE'
  | 'DESCRIPTOR_DOMAIN_MISMATCH'
  | 'DESCRIPTOR_UNSUPPORTED_VERSION'
  | 'DESCRIPTOR_SERVER_KEY_INVALID'
  | 'DESCRIPTOR_SERVER_ID_MISMATCH'
  | 'DESCRIPTOR_TIMESTAMPS_INVALID'
  | 'DESCRIPTOR_EXPIRED'
  | 'DESCRIPTOR_LIFETIME_EXCEEDED'
  | 'DESCRIPTOR_EMPTY_CANDIDATES'
  | 'DESCRIPTOR_MAX_CANDIDATES_EXCEEDED'
  | 'DESCRIPTOR_CANDIDATE_INVALID'
  | 'DESCRIPTOR_CANDIDATE_DUPLICATE'
  | 'DESCRIPTOR_NOT_CANONICAL_ORDER'
  | 'DESCRIPTOR_SIGNATURE_INVALID'
  | 'DESCRIPTOR_TRAILING_BYTES'
  | 'DESCRIPTOR_HANDLE_CLOSED'

const ERROR_MESSAGES: Record<ConnectivityDescriptorErrorCode, string> = {
  DESCRIPTOR_INVALID_SIZE: 'O tamanho do descritor de conectividade é inválido ou excede o limite máximo.',
  DESCRIPTOR_DOMAIN_MISMATCH: 'Domínio de separação criptográfica inválido para o descritor de conectividade.',
  DESCRIPTOR_UNSUPPORTED_VERSION: 'Versão do descritor de conectividade não suportada.',
  DESCRIPTOR_SERVER_KEY_INVALID: 'A chave pública do servidor no descritor é inválida ou malformada.',
  DESCRIPTOR_SERVER_ID_MISMATCH: 'O serverId contido no descritor não corresponde à chave pública ou ao esperado.',
  DESCRIPTOR_TIMESTAMPS_INVALID: 'Os timestamps de emissão e expiração do descritor são inválidos.',
  DESCRIPTOR_EXPIRED: 'O descritor de conectividade está expirado segundo o relógio local.',
  DESCRIPTOR_LIFETIME_EXCEEDED: 'O tempo de vida solicitado para o descritor excede o limite máximo permitido.',
  DESCRIPTOR_EMPTY_CANDIDATES: 'O descritor deve conter ao menos um Connectivity Candidate válido.',
  DESCRIPTOR_MAX_CANDIDATES_EXCEEDED: 'A quantidade de candidates excede o limite máximo permitido.',
  DESCRIPTOR_CANDIDATE_INVALID: 'Um dos Connectivity Candidates é inválido, não permitido ou malformado.',
  DESCRIPTOR_CANDIDATE_DUPLICATE: 'Existem candidates duplicados no conjunto a ser assinado.',
  DESCRIPTOR_NOT_CANONICAL_ORDER: 'Os Connectivity Candidates não estão na ordem canônica estrita.',
  DESCRIPTOR_SIGNATURE_INVALID: 'A assinatura Ed25519 do descritor de conectividade é inválida ou forjada.',
  DESCRIPTOR_TRAILING_BYTES: 'O payload codificado contém bytes excedentes não permitidos após o descriptor.',
  DESCRIPTOR_HANDLE_CLOSED: 'O listener TCP fornecido para geração do candidate já foi encerrado ou é inválido.'
}

export class ConnectivityDescriptorError extends Error {
  readonly code: ConnectivityDescriptorErrorCode

  constructor(code: ConnectivityDescriptorErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'ConnectivityDescriptorError'
    this.code = code
  }
}

export function compareCandidates(a: ConnectivityCandidate, b: ConnectivityCandidate): number {
  if (a.candidateType !== b.candidateType) {
    return a.candidateType - b.candidateType
  }
  if (a.family !== b.family) {
    return a.family - b.family
  }
  const addrComp = a.address.localeCompare(b.address)
  if (addrComp !== 0) {
    return addrComp
  }
  return a.port - b.port
}

function candidateScopeToByte(candidate: ConnectivityCandidate): number {
  if (candidate.candidateType === ConnectivityCandidateType.LAN_TCP) {
    switch (candidate.scope) {
      case 'LAN_PRIVATE':
        return 1
      case 'LINK_LOCAL':
        return 2
      case 'LOOPBACK':
        return 3
    }
  }
  return 0 // PORT_MAPPED_TCP e DIRECT_GLOBAL_TCP usam 0 (GLOBAL)
}

function byteToCandidateScope(b: number): CandidateScope | null {
  switch (b) {
    case 1:
      return 'LAN_PRIVATE'
    case 2:
      return 'LINK_LOCAL'
    case 3:
      return 'LOOPBACK'
    default:
      return null
  }
}

/**
 * Monta o payload binário canônico para assinatura Ed25519 e verificação.
 */
function buildCanonicalPayload(
  serverId: string,
  serverPublicKey: Buffer,
  descriptorId: Buffer,
  issuedAt: number,
  expiresAt: number,
  candidates: readonly ConnectivityCandidate[]
): Buffer {
  const domainBuf = Buffer.from(CONNECTIVITY_DESCRIPTOR_DOMAIN, 'utf8')
  const serverIdBuf = Buffer.from(serverId, 'utf8')

  const chunks: Buffer[] = []

  // 1. Domain prefix (1 byte length + utf8)
  const domainHeader = Buffer.alloc(1 + domainBuf.length)
  domainHeader.writeUInt8(domainBuf.length, 0)
  domainBuf.copy(domainHeader, 1)
  chunks.push(domainHeader)

  // 2. Version (1 byte: 1) + Type (1 byte: 1)
  const verType = Buffer.alloc(2)
  verType.writeUInt8(CONNECTIVITY_DESCRIPTOR_VERSION, 0)
  verType.writeUInt8(1, 1) // 1 = connectivity-descriptor
  chunks.push(verType)

  // 3. ServerId (1 byte length + utf8)
  const serverIdHeader = Buffer.alloc(1 + serverIdBuf.length)
  serverIdHeader.writeUInt8(serverIdBuf.length, 0)
  serverIdBuf.copy(serverIdHeader, 1)
  chunks.push(serverIdHeader)

  // 4. ServerPublicKey (2 bytes length + raw SPKI DER)
  const pubKeyHeader = Buffer.alloc(2 + serverPublicKey.length)
  pubKeyHeader.writeUInt16BE(serverPublicKey.length, 0)
  serverPublicKey.copy(pubKeyHeader, 2)
  chunks.push(pubKeyHeader)

  // 5. DescriptorId (32 bytes)
  chunks.push(Buffer.from(descriptorId))

  // 6. Timestamps (BigInt uint64BE para issuedAt e expiresAt)
  const timesBuf = Buffer.alloc(16)
  timesBuf.writeBigUInt64BE(BigInt(issuedAt), 0)
  timesBuf.writeBigUInt64BE(BigInt(expiresAt), 8)
  chunks.push(timesBuf)

  // 7. CandidateCount (1 byte)
  const countBuf = Buffer.alloc(1)
  countBuf.writeUInt8(candidates.length, 0)
  chunks.push(countBuf)

  // 8. Candidates
  for (const c of candidates) {
    const addrBuf = Buffer.from(c.address, 'utf8')
    const cBuf = Buffer.alloc(1 + 1 + 1 + addrBuf.length + 2 + 1)
    let offset = 0
    cBuf.writeUInt8(c.candidateType, offset++)
    cBuf.writeUInt8(c.family, offset++)
    cBuf.writeUInt8(addrBuf.length, offset++)
    addrBuf.copy(cBuf, offset)
    offset += addrBuf.length
    cBuf.writeUInt16BE(c.port, offset)
    offset += 2
    cBuf.writeUInt8(candidateScopeToByte(c), offset)
    chunks.push(cBuf)
  }

  return Buffer.concat(chunks)
}

export interface CreateConnectivityDescriptorOptions {
  readonly serverId: string
  readonly serverPublicKey: Buffer
  readonly serverPrivateKey: KeyObject
  readonly candidates: readonly (
    | ConnectivityCandidate
    | BoundTcpEndpoint
    | LanTcpServerHandle
    | ActivePortMappingSource
    | ActiveDirectGlobalListener
  )[]
  readonly lifetimeSeconds?: number
  readonly allowLoopbackForTesting?: boolean
  readonly allowRawCandidatesForTesting?: boolean
  readonly customIssuedAt?: number
  readonly customDescriptorId?: Buffer
}

/**
 * Converte entradas de listener ou endpoint para ConnectivityCandidate canônico validado.
 */
function normalizeCandidateInput(
  rawInput: ConnectivityCandidate | BoundTcpEndpoint | LanTcpServerHandle | ActivePortMappingSource | ActiveDirectGlobalListener,
  allowLoopbackForTesting = false,
  allowRawCandidatesForTesting = false
): ConnectivityCandidate {
  let candidateType: ConnectivityCandidateType
  let address: string
  let port: number
  let family: 4 | 6

  if (isLegitimateActiveDirectGlobalListener(rawInput)) {
    // Capability runtime legítima, revalidada imediatamente antes da assinatura.
    if (!rawInput.isActive()) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_HANDLE_CLOSED')
    }
    const endpoint = rawInput.getBoundEndpoint()
    candidateType = ConnectivityCandidateType.DIRECT_GLOBAL_TCP
    address = endpoint.address
    port = endpoint.port
    family = 6
  } else if (isLegitimateActivePortMapping(rawInput)) {
    // Runtime capability legítima de Port Mapping (ActivePortMapping)
    if (!rawInput.isActive()) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_HANDLE_CLOSED')
    }
    const remainingLease = rawInput.getExpiresAt() - Math.floor(Date.now() / 1000)
    if (remainingLease < MIN_MAPPING_REMAINING_FOR_DESCRIPTOR_SECONDS) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }
    const ext = rawInput.getExternalEndpoint()
    candidateType = ConnectivityCandidateType.PORT_MAPPED_TCP
    address = ext.address
    port = ext.port
    family = ext.family
  } else if ('endpoint' in rawInput) {
    // Runtime handle legítimo (LanTcpServerHandle)
    const handle = rawInput as LanTcpServerHandle
    if (!isLegitimateActiveServerHandle(handle)) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_HANDLE_CLOSED')
    }
    if (typeof handle.isClosed === 'function' && handle.isClosed()) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_HANDLE_CLOSED')
    }
    candidateType = ConnectivityCandidateType.LAN_TCP
    address = handle.endpoint.address
    port = handle.endpoint.port
    family = handle.endpoint.family
  } else if ('candidateType' in rawInput) {
    // Objeto ConnectivityCandidate explícito (requer allowRawCandidatesForTesting para evitar forgery em produção)
    if (!allowRawCandidatesForTesting) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }
    candidateType = rawInput.candidateType
    address = rawInput.address
    port = rawInput.port
    family = rawInput.family
  } else if ('address' in rawInput && 'port' in rawInput && 'family' in rawInput) {
    // BoundTcpEndpoint
    if (!allowRawCandidatesForTesting) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }
    candidateType = ConnectivityCandidateType.LAN_TCP
    address = rawInput.address
    port = rawInput.port
    family = rawInput.family
  } else {
    throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
  }

  if (typeof address !== 'string' || address.trim().length === 0) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
  }

  const trimmed = address.trim()
  const ipVer = isIP(trimmed)
  if ((ipVer !== 4 && ipVer !== 6) || ipVer !== family) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
  }

  assertValidPort(port, false)
  const classification = classifyNetworkAddress(trimmed)

  if (candidateType === ConnectivityCandidateType.LAN_TCP) {
    if (
      classification.scope === 'GLOBAL' ||
      classification.scope === 'CGNAT' ||
      classification.scope === 'DOCUMENTATION' ||
      classification.scope === 'BENCHMARK' ||
      classification.scope === 'UNSPECIFIED' ||
      classification.scope === 'MULTICAST' ||
      classification.scope === 'RESERVED' ||
      classification.scope === 'UNSUPPORTED'
    ) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }

    if (classification.scope === 'LOOPBACK') {
      if (!allowLoopbackForTesting) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }
      return {
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family,
        address: classification.normalizedAddress,
        port,
        scope: 'LOOPBACK'
      }
    }

    const scope: CandidateScope =
      classification.scope === 'LINK_LOCAL' ? 'LINK_LOCAL' : 'LAN_PRIVATE'

    return {
      candidateType: ConnectivityCandidateType.LAN_TCP,
      family,
      address: classification.normalizedAddress,
      port,
      scope
    }
  } else if (
    candidateType === ConnectivityCandidateType.PORT_MAPPED_TCP ||
    candidateType === ConnectivityCandidateType.DIRECT_GLOBAL_TCP
  ) {
    // WAN Candidates: exigem obrigatoriamente endereço globalmente roteável (Global Unicast)
    if (!classification.isGloballyRoutableWan || classification.scope !== 'GLOBAL') {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }

    if (candidateType === ConnectivityCandidateType.PORT_MAPPED_TCP) {
      return {
        candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
        family,
        address: classification.normalizedAddress,
        port
      }
    } else {
      if (family !== 6 || classification.family !== 'IPv6' || classification.normalizedAddress.startsWith('::ffff:')) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }
      return {
        candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
        family,
        address: classification.normalizedAddress,
        port
      }
    }
  } else {
    throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
  }
}

/**
 * Cria e assina criptograficamente um SignedConnectivityDescriptor autenticado pela Server Identity.
 */
export function createSignedConnectivityDescriptor(
  options: CreateConnectivityDescriptorOptions
): Buffer {
  if (!options.candidates || options.candidates.length === 0) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_EMPTY_CANDIDATES')
  }

  if (options.candidates.length > MAX_CONNECTIVITY_CANDIDATES) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_MAX_CANDIDATES_EXCEEDED')
  }

  // 1. Normaliza e valida candidates
  const normalizedCandidates: ConnectivityCandidate[] = []
  const seenKeys = new Set<string>()

  for (const raw of options.candidates) {
    const candidate = normalizeCandidateInput(
      raw,
      options.allowLoopbackForTesting,
      options.allowRawCandidatesForTesting
    )
    const key = `${candidate.candidateType}|${candidate.family}|${candidate.address}|${candidate.port}`
    if (seenKeys.has(key)) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_DUPLICATE')
    }
    seenKeys.add(key)
    normalizedCandidates.push(candidate)
  }

  // 2. Ordenação canônica estrita
  normalizedCandidates.sort(compareCandidates)

  // 3. Validação do ServerId recalculado
  if (!options.serverPublicKey || options.serverPublicKey.length === 0) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SERVER_KEY_INVALID')
  }

  const expectedServerId =
    'sha256:' + createHash('sha256').update(options.serverPublicKey).digest('hex')
  if (options.serverId !== expectedServerId) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SERVER_ID_MISMATCH')
  }

  // 4. Timestamps e lifetime
  const now = options.customIssuedAt ?? Math.floor(Date.now() / 1000)
  const lifetime = options.lifetimeSeconds ?? DEFAULT_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS

  if (lifetime <= 0 || lifetime > MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_LIFETIME_EXCEEDED')
  }

  // Clampa o lifetime do descritor pela menor lease de ActivePortMapping presente
  let maxAllowedExpiresAt = now + lifetime
  for (const raw of options.candidates) {
    if (isLegitimateActivePortMapping(raw)) {
      if (!raw.isActive()) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_HANDLE_CLOSED')
      }
      maxAllowedExpiresAt = Math.min(maxAllowedExpiresAt, raw.getExpiresAt())
    }
  }

  const issuedAt = now
  const expiresAt = maxAllowedExpiresAt

  if (expiresAt <= issuedAt) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
  }

  // 5. DescriptorId
  let descriptorId: Buffer
  if (options.customDescriptorId) {
    if (options.customDescriptorId.length !== DESCRIPTOR_ID_BYTES) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_INVALID_SIZE')
    }
    descriptorId = Buffer.from(options.customDescriptorId)
  } else {
    descriptorId = randomBytes(DESCRIPTOR_ID_BYTES)
  }

  // 6. Monta canonical payload
  const canonicalPayload = buildCanonicalPayload(
    options.serverId,
    options.serverPublicKey,
    descriptorId,
    issuedAt,
    expiresAt,
    normalizedCandidates
  )

  // 7. Assina com Ed25519
  const signature = sign(null, canonicalPayload, options.serverPrivateKey)
  if (signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SIGNATURE_INVALID')
  }

  const fullEncoded = Buffer.concat([canonicalPayload, signature])
  if (fullEncoded.length > MAX_CONNECTIVITY_DESCRIPTOR_BYTES) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_INVALID_SIZE')
  }

  return fullEncoded
}

export interface VerifyConnectivityDescriptorOptions {
  readonly encodedDescriptor: Buffer
  readonly expectedServerId?: string
  readonly nowSeconds?: number
  readonly allowLoopbackForTesting?: boolean
}

/**
 * Decodifica, valida formato estrito e verifica a assinatura Ed25519 de um SignedConnectivityDescriptor.
 */
export function verifySignedConnectivityDescriptor(
  options: VerifyConnectivityDescriptorOptions
): VerifiedConnectivityDescriptor {
  const buf = options.encodedDescriptor
  if (!Buffer.isBuffer(buf) || buf.length < 128 || buf.length > MAX_CONNECTIVITY_DESCRIPTOR_BYTES) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_INVALID_SIZE')
  }

  const signature = buf.subarray(buf.length - ED25519_SIGNATURE_BYTES)
  const canonicalPayload = buf.subarray(0, buf.length - ED25519_SIGNATURE_BYTES)

  let offset = 0

  // 1. Domain
  const domainLen = canonicalPayload.readUInt8(offset++)
  const domain = canonicalPayload.subarray(offset, offset + domainLen).toString('utf8')
  offset += domainLen
  if (domain !== CONNECTIVITY_DESCRIPTOR_DOMAIN) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_DOMAIN_MISMATCH')
  }

  // 2. Version & Type
  const version = canonicalPayload.readUInt8(offset++)
  const typeByte = canonicalPayload.readUInt8(offset++)
  if (version !== CONNECTIVITY_DESCRIPTOR_VERSION || typeByte !== 1) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_UNSUPPORTED_VERSION')
  }

  // 3. ServerId
  const serverIdLen = canonicalPayload.readUInt8(offset++)
  const serverId = canonicalPayload.subarray(offset, offset + serverIdLen).toString('utf8')
  offset += serverIdLen

  if (options.expectedServerId && serverId !== options.expectedServerId) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SERVER_ID_MISMATCH')
  }

  // 4. ServerPublicKey
  const pubKeyLen = canonicalPayload.readUInt16BE(offset)
  offset += 2
  const serverPublicKey = Buffer.from(canonicalPayload.subarray(offset, offset + pubKeyLen))
  offset += pubKeyLen

  // Valida integridade entre serverPublicKey e serverId
  const derivedServerId =
    'sha256:' + createHash('sha256').update(serverPublicKey).digest('hex')
  if (serverId !== derivedServerId) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SERVER_ID_MISMATCH')
  }

  // 5. DescriptorId
  const descriptorId = Buffer.from(canonicalPayload.subarray(offset, offset + DESCRIPTOR_ID_BYTES))
  offset += DESCRIPTOR_ID_BYTES

  // 6. Timestamps
  const issuedAt = Number(canonicalPayload.readBigUInt64BE(offset))
  offset += 8
  const expiresAt = Number(canonicalPayload.readBigUInt64BE(offset))
  offset += 8

  if (issuedAt <= 0 || expiresAt <= issuedAt) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_TIMESTAMPS_INVALID')
  }

  const lifetime = expiresAt - issuedAt
  if (lifetime > MAX_CONNECTIVITY_DESCRIPTOR_LIFETIME_SECONDS) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_LIFETIME_EXCEEDED')
  }

  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000)
  if (now >= expiresAt) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_EXPIRED')
  }

  // 7. CandidateCount
  const candidateCount = canonicalPayload.readUInt8(offset++)
  if (candidateCount === 0) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_EMPTY_CANDIDATES')
  }
  if (candidateCount > MAX_CONNECTIVITY_CANDIDATES) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_MAX_CANDIDATES_EXCEEDED')
  }

  // 8. Candidates
  const candidates: ConnectivityCandidate[] = []
  const seenKeys = new Set<string>()

  for (let i = 0; i < candidateCount; i++) {
    if (offset >= canonicalPayload.length) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_INVALID_SIZE')
    }

    const cType = canonicalPayload.readUInt8(offset++)
    if (
      cType !== ConnectivityCandidateType.LAN_TCP &&
      cType !== ConnectivityCandidateType.PORT_MAPPED_TCP &&
      cType !== ConnectivityCandidateType.DIRECT_GLOBAL_TCP
    ) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }

    const fam = canonicalPayload.readUInt8(offset++)
    if (fam !== 4 && fam !== 6) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }

    const addrLen = canonicalPayload.readUInt8(offset++)
    const addr = canonicalPayload.subarray(offset, offset + addrLen).toString('utf8')
    offset += addrLen

    const port = canonicalPayload.readUInt16BE(offset)
    offset += 2
    if (port < 1 || port > 65535) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }

    const scopeByte = canonicalPayload.readUInt8(offset++)
    const classification = classifyNetworkAddress(addr)

    let candidate: ConnectivityCandidate

    if (cType === ConnectivityCandidateType.LAN_TCP) {
      const scope = byteToCandidateScope(scopeByte)
      if (!scope) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }

      if (
        classification.scope === 'GLOBAL' ||
        classification.scope === 'CGNAT' ||
        classification.scope === 'DOCUMENTATION' ||
        classification.scope === 'BENCHMARK' ||
        classification.scope === 'UNSPECIFIED' ||
        classification.scope === 'MULTICAST' ||
        classification.scope === 'RESERVED' ||
        classification.scope === 'UNSUPPORTED'
      ) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }

      if (scope === 'LOOPBACK' && !options.allowLoopbackForTesting) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }

      candidate = Object.freeze({
        candidateType: ConnectivityCandidateType.LAN_TCP,
        family: fam as 4 | 6,
        address: classification.normalizedAddress,
        port,
        scope
      })
    } else if (cType === ConnectivityCandidateType.PORT_MAPPED_TCP) {
      if (scopeByte !== 0 || !classification.isGloballyRoutableWan || classification.scope !== 'GLOBAL') {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }

      candidate = Object.freeze({
        candidateType: ConnectivityCandidateType.PORT_MAPPED_TCP,
        family: fam as 4 | 6,
        address: classification.normalizedAddress,
        port
      })
    } else {
      // DIRECT_GLOBAL_TCP
      if (
        fam !== 6 ||
        scopeByte !== 0 ||
        classification.family !== 'IPv6' ||
        classification.normalizedAddress.startsWith('::ffff:') ||
        !classification.isGloballyRoutableWan ||
        classification.scope !== 'GLOBAL'
      ) {
        throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
      }

      candidate = Object.freeze({
        candidateType: ConnectivityCandidateType.DIRECT_GLOBAL_TCP,
        family: 6,
        address: classification.normalizedAddress,
        port
      })
    }

    const key = `${candidate.candidateType}|${candidate.family}|${candidate.address}|${candidate.port}`
    if (seenKeys.has(key)) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_DUPLICATE')
    }
    seenKeys.add(key)
    candidates.push(candidate)
  }

  // Validação de trailing bytes
  if (offset !== canonicalPayload.length) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_TRAILING_BYTES')
  }

  // Validação de ordenação canônica
  const sorted = [...candidates].sort(compareCandidates)
  for (let i = 0; i < candidates.length; i++) {
    if (
      candidates[i]!.candidateType !== sorted[i]!.candidateType ||
      candidates[i]!.family !== sorted[i]!.family ||
      candidates[i]!.address !== sorted[i]!.address ||
      candidates[i]!.port !== sorted[i]!.port
    ) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_NOT_CANONICAL_ORDER')
    }
  }

  // 9. Verificação criptográfica Ed25519
  let isSigValid: boolean
  try {
    const pubKeyObject = createPublicKey({
      key: serverPublicKey,
      format: 'der',
      type: 'spki'
    })
    isSigValid = verify(null, canonicalPayload, pubKeyObject, signature)
  } catch {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SIGNATURE_INVALID')
  }

  if (!isSigValid) {
    throw new ConnectivityDescriptorError('DESCRIPTOR_SIGNATURE_INVALID')
  }

  return Object.freeze({
    version: 1,
    type: 'connectivity-descriptor',
    serverId,
    serverPublicKey,
    descriptorId,
    issuedAt,
    expiresAt,
    candidates: Object.freeze(candidates),
    signature,
    rawEncoded: buf
  })
}

/**
 * Converte candidates verificados em DirectTcpEndpoint para conexão pelo cliente.
 */
export function extractDirectTcpEndpoints(
  descriptor: VerifiedConnectivityDescriptor
): readonly DirectTcpEndpoint[] {
  return descriptor.candidates.map((c) => ({
    family: c.family,
    address: c.address,
    port: c.port
  }))
}

export function resolveAdvertisedCandidate(
  candidate: ConnectivityCandidate,
  localScopeId?: number
): DirectTcpEndpoint {
  if (candidate.candidateType === ConnectivityCandidateType.LAN_TCP && candidate.family === 6 && candidate.scope === 'LINK_LOCAL') {
    if (typeof localScopeId !== 'number' || localScopeId < 0) {
      throw new ConnectivityDescriptorError('DESCRIPTOR_CANDIDATE_INVALID')
    }
    return {
      family: 6,
      address: candidate.address,
      port: candidate.port,
      scopeId: localScopeId
    }
  }
  return {
    family: candidate.family,
    address: candidate.address,
    port: candidate.port
  }
}
