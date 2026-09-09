import { createPrivateKey, randomBytes } from 'node:crypto'
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rm,
  rmdir,
  unlink
} from 'node:fs/promises'
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path'
import type { DatabaseSync } from 'node:sqlite'

import {
  InitialOwnerBindingError,
  loadInitialOwnerBinding,
  MAX_INITIAL_OWNER_METADATA_BYTES,
  type InitialOwnerBinding,
  type InitialOwnerDeviceIdentity
} from './initial-owner-binding'
import {
  createChannel,
  createMessage,
  createMessageOperationAuthorization,
  deleteChannel,
  deleteMessage,
  editMessage,
  listChannels,
  listMessages,
  renameChannel,
  setChannelArchived,
  type ServerChannel,
  type ServerMessage,
  DATABASE_FILE_NAME,
  admitMemberWithInvite,
  consumeServerInvite,
  getStoredInvite,
  initializeServerDatabase,
  openServerDatabase,
  registerIssuedInvite,
  revokeServerInvite,
  ServerDatabaseError,
  validateServerDatabaseFile,
  verifyPersistedMemberAuthorization,
  type AuthenticatedCandidateDevice,
  type Member,
  type StoredInvite,
  type VerifiedMemberAuthorization
} from './server-database'
import {
  assertServerIdentitySecureStorageAvailable,
  createServerIdentityMaterial,
  isValidServerId,
  loadServerIdentity,
  MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
  MAX_SERVER_IDENTITY_METADATA_BYTES,
  ServerIdentityError,
  type ServerIdentity,
  type ServerIdentityMaterial,
  type ServerIdentitySafeStorage
} from './server-identity'
import {
  createServerInvite,
  encodeServerInvite,
  ServerInviteError,
  type CreateServerInviteOptions,
  type ServerInvite
} from './server-invite'

const SERVER_METADATA_VERSION = 1
const SERVERS_DIRECTORY_NAME = 'servers'
const METADATA_FILE_NAME = 'server.json'
const IDENTITY_DIRECTORY_NAME = 'identity'
const IDENTITY_METADATA_FILE_NAME = 'identity.json'
const PRIVATE_KEY_FILE_NAME = 'private-key.enc'
const AUTHORITY_DIRECTORY_NAME = 'authority'
const OWNER_METADATA_FILE_NAME = 'owner.json'
const STORAGE_ID_PATTERN = /^[0-9a-f]{32}$/

export const MAX_DISPLAY_NAME_CODE_POINTS = 100
export const MAX_SERVER_METADATA_BYTES = 4 * 1024
export const MAX_STORAGE_ID_COLLISION_ATTEMPTS = 5

export type LocalServerStorageErrorCode =
  | 'INVALID_SERVER_NAME'
  | 'INVALID_STORAGE_ID'
  | 'SERVER_NOT_FOUND'
  | 'SERVER_METADATA_CORRUPTED'
  | 'SERVER_VERSION_UNSUPPORTED'
  | 'SERVER_PATH_UNSAFE'
  | 'SERVER_IDENTITY_CORRUPTED'
  | 'SERVER_IDENTITY_PATH_UNSAFE'
  | 'SERVER_IDENTITY_ID_MISMATCH'
  | 'SERVER_OWNER_BINDING_INVALID'
  | 'SERVER_OWNER_BINDING_PATH_UNSAFE'
  | 'SERVER_DATABASE_NOT_FOUND'
  | 'SERVER_DATABASE_PATH_UNSAFE'
  | 'SERVER_DATABASE_CORRUPTED'
  | 'SERVER_DATABASE_SCHEMA_INVALID'
  | 'SERVER_DATABASE_VERSION_UNSUPPORTED'
  | 'SERVER_DATABASE_TOO_LARGE'
  | 'SERVER_DATABASE_INITIALIZATION_FAILED'
  | 'SERVER_MEMBERSHIP_STATE_INVALID'
  | 'SERVER_MEMBER_CERTIFICATE_INVALID'
  | 'SERVER_MEMBER_CERTIFICATE_MISSING'
  | 'SERVER_MEMBER_CERTIFICATE_UNEXPECTED'
  | 'SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION'
  | 'SERVER_INVITE_INVALID'
  | 'SERVER_INVITE_VERSION_UNSUPPORTED'
  | 'SERVER_INVITE_EXPIRED'
  | 'SERVER_INVITE_UNAUTHORIZED'
  | 'SERVER_INVITE_CREATION_FAILED'
  | 'SERVER_INVITE_SERVER_MISMATCH'
  | 'SERVER_INVITE_NOT_FOUND'
  | 'SERVER_INVITE_STATE_INVALID'
  | 'SERVER_INVITE_EXHAUSTED'
  | 'SERVER_INVITE_REVOKED'
  | 'SERVER_MEMBER_ALREADY_EXISTS'
  | 'SERVER_ADMISSION_INVALID_CANDIDATE'
  | 'SERVER_ADMISSION_FAILED'
  | 'SERVER_CHANNEL_INVALID'
  | 'SERVER_CHANNEL_NOT_FOUND'
  | 'SERVER_CHANNEL_ALREADY_EXISTS'
  | 'SERVER_CHANNEL_LIMIT_REACHED'
  | 'SERVER_CHANNEL_UNAUTHORIZED'
  | 'SERVER_CHANNEL_ARCHIVED'
  | 'SERVER_MESSAGE_INVALID'
  | 'SERVER_MESSAGE_NOT_FOUND'
  | 'SERVER_MESSAGE_FORBIDDEN'
  | 'SERVER_MESSAGE_CAPACITY_REACHED'
  | 'SERVER_MESSAGE_DUPLICATE'
  | 'SERVER_CREATION_FAILED'
  | 'SERVER_ID_COLLISION_LIMIT'

const ERROR_MESSAGES: Record<LocalServerStorageErrorCode, string> = {
  INVALID_SERVER_NAME: 'O nome do servidor é inválido.',
  INVALID_STORAGE_ID: 'O identificador local do servidor é inválido.',
  SERVER_NOT_FOUND: 'O servidor local não foi encontrado.',
  SERVER_METADATA_CORRUPTED: 'Os metadados locais do servidor são inválidos.',
  SERVER_VERSION_UNSUPPORTED: 'A versão dos metadados do servidor não é suportada.',
  SERVER_PATH_UNSAFE: 'A estrutura local do servidor não é segura.',
  SERVER_IDENTITY_CORRUPTED: 'A identidade criptográfica do servidor é inválida.',
  SERVER_IDENTITY_PATH_UNSAFE: 'A estrutura da identidade do servidor não é segura.',
  SERVER_IDENTITY_ID_MISMATCH: 'A identidade não corresponde aos metadados do servidor.',
  SERVER_OWNER_BINDING_INVALID: 'O vínculo de autoridade inicial do servidor é inválido.',
  SERVER_OWNER_BINDING_PATH_UNSAFE: 'A estrutura da autoridade inicial não é segura.',
  SERVER_DATABASE_NOT_FOUND: 'O banco de dados do servidor não foi encontrado.',
  SERVER_DATABASE_PATH_UNSAFE: 'A estrutura do banco de dados do servidor não é segura.',
  SERVER_DATABASE_CORRUPTED: 'O banco de dados do servidor está corrompido ou é inválido.',
  SERVER_DATABASE_SCHEMA_INVALID: 'O esquema do banco de dados do servidor é inválido.',
  SERVER_DATABASE_VERSION_UNSUPPORTED: 'A versão do esquema do banco de dados do servidor não é suportada.',
  SERVER_DATABASE_TOO_LARGE: 'O banco de dados do servidor excede o tamanho máximo permitido.',
  SERVER_DATABASE_INITIALIZATION_FAILED: 'Não foi possível inicializar o banco de dados do servidor com segurança.',
  SERVER_MEMBERSHIP_STATE_INVALID: 'O estado de membros do servidor é inválido ou inconsistente com a autoridade.',
  SERVER_MEMBER_CERTIFICATE_INVALID: 'O certificado de membro é inválido ou forjado.',
  SERVER_MEMBER_CERTIFICATE_MISSING: 'Membro não-owner persistido sem certificado criptográfico da Server Identity.',
  SERVER_MEMBER_CERTIFICATE_UNEXPECTED: 'Certificado de membro inesperado para o Initial Owner.',
  SERVER_MEMBERSHIP_MIGRATION_REQUIRES_READMISSION: 'Migração de banco legado v3 com membros não-owner exige nova admissão criptográfica.',
  SERVER_INVITE_INVALID: 'O convite do servidor é inválido ou está malformado.',
  SERVER_INVITE_VERSION_UNSUPPORTED: 'A versão do convite não é suportada.',
  SERVER_INVITE_EXPIRED: 'O convite do servidor expirou.',
  SERVER_INVITE_UNAUTHORIZED: 'Apenas a autoridade inicial do servidor pode emitir convites.',
  SERVER_INVITE_CREATION_FAILED: 'Não foi possível criar o convite do servidor com segurança.',
  SERVER_INVITE_SERVER_MISMATCH: 'O convite não pertence ao servidor especificado.',
  SERVER_INVITE_NOT_FOUND: 'O convite do servidor não foi encontrado.',
  SERVER_INVITE_STATE_INVALID: 'O estado persistido do convite é inválido ou inconsistente.',
  SERVER_INVITE_EXHAUSTED: 'O convite do servidor já atingiu o limite máximo de utilizações.',
  SERVER_INVITE_REVOKED: 'O convite do servidor foi revogado.',
  SERVER_MEMBER_ALREADY_EXISTS: 'A identidade do dispositivo candidato já é membro do servidor.',
  SERVER_ADMISSION_INVALID_CANDIDATE: 'A identidade do dispositivo candidato é inválida.',
  SERVER_ADMISSION_FAILED: 'Não foi possível admitir o novo membro no servidor com segurança.',
  SERVER_CHANNEL_INVALID: 'O canal solicitado é inválido.',
  SERVER_CHANNEL_NOT_FOUND: 'O canal do servidor não foi encontrado.',
  SERVER_CHANNEL_ALREADY_EXISTS: 'Já existe um canal com esse nome no servidor.',
  SERVER_CHANNEL_LIMIT_REACHED: 'O servidor atingiu o número máximo de canais.',
  SERVER_CHANNEL_UNAUTHORIZED: 'Apenas o owner pode gerenciar canais do servidor.',
  SERVER_CHANNEL_ARCHIVED: 'O canal está arquivado e não aceita novas mensagens.',
  SERVER_MESSAGE_INVALID: 'A mensagem solicitada é inválida.',
  SERVER_MESSAGE_NOT_FOUND: 'A mensagem do servidor não foi encontrada.',
  SERVER_MESSAGE_FORBIDDEN: 'A operação de mensagem não é permitida para este membro.',
  SERVER_MESSAGE_CAPACITY_REACHED: 'O canal atingiu o número máximo de mensagens vivas.',
  SERVER_MESSAGE_DUPLICATE: 'A mensagem duplicada já foi registrada para este canal.',
  SERVER_CREATION_FAILED: 'Não foi possível criar o servidor local com segurança.',
  SERVER_ID_COLLISION_LIMIT: 'Não foi possível reservar um identificador local único.'
}

export class LocalServerStorageError extends Error {
  readonly code: LocalServerStorageErrorCode

  constructor(code: LocalServerStorageErrorCode) {
    super(ERROR_MESSAGES[code])
    this.name = 'LocalServerStorageError'
    this.code = code
  }
}

export interface LocalServerMetadata {
  readonly version: typeof SERVER_METADATA_VERSION
  readonly localStorageId: string
  readonly displayName: string
  readonly serverId: string
}

export interface LocalServer extends LocalServerMetadata {
  readonly identity: ServerIdentity
  readonly initialOwner: InitialOwnerBinding
}

interface LocalServerStorageOptions {
  readonly generateStorageId?: () => string
  readonly platform?: NodeJS.Platform
  readonly createIdentityMaterial?: (
    secureStorage: ServerIdentitySafeStorage,
    ownerDeviceIdentity: InitialOwnerDeviceIdentity,
    platform: NodeJS.Platform
  ) => ServerIdentityMaterial
}

export type LocalServerStorage = ReturnType<typeof createLocalServerStorage>

export function createLocalServerStorage(
  userDataDirectory: string,
  secureStorage: ServerIdentitySafeStorage,
  ownerDeviceIdentity: InitialOwnerDeviceIdentity,
  options: LocalServerStorageOptions = {}
) {
  const serversRoot = deriveServersRoot(userDataDirectory)
  const generateStorageId = options.generateStorageId ?? generateLocalStorageId
  const platform = options.platform ?? process.platform
  const createIdentityMaterial = options.createIdentityMaterial ?? createServerIdentityMaterial

  return Object.freeze({
    createLocalServer: async (displayName: string): Promise<LocalServer> => {
      assertValidDisplayName(displayName)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await ensureServersRoot(serversRoot)

      for (let attempt = 0; attempt < MAX_STORAGE_ID_COLLISION_ATTEMPTS; attempt += 1) {
        const localStorageId = generateStorageId()

        if (!isValidStorageId(localStorageId)) {
          throw new LocalServerStorageError('SERVER_CREATION_FAILED')
        }

        let identityMaterial: ServerIdentityMaterial

        try {
          identityMaterial = createIdentityMaterial(
            secureStorage,
            ownerDeviceIdentity,
            platform
          )
        } catch (error) {
          if (error instanceof ServerIdentityError) {
            throw error
          }

          throw new ServerIdentityError('SERVER_IDENTITY_CRYPTO_FAILED')
        }
        const created = await tryCreateLocalServer(
          serversRoot,
          rootRealPath,
          localStorageId,
          displayName,
          identityMaterial,
          ownerDeviceIdentity,
          secureStorage,
          platform
        )

        if (created) {
          return created
        }
      }

      throw new LocalServerStorageError('SERVER_ID_COLLISION_LIMIT')
    },

    loadLocalServer: async (localStorageId: string): Promise<LocalServer> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      return loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )
    },

    createLocalServerInvite: async (
      localStorageId: string,
      options: CreateServerInviteOptions
    ): Promise<{ invite: ServerInvite; encoded: string }> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      if (
        server.initialOwner.deviceFingerprint !== ownerDeviceIdentity.fingerprint ||
        !server.initialOwner.publicKey.equals(ownerDeviceIdentity.publicKey)
      ) {
        throw new LocalServerStorageError('SERVER_INVITE_UNAUTHORIZED')
      }

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const serverRealPath = await inspectDirectChildDirectory(
        serverDirectory,
        rootRealPath,
        localStorageId,
        'SERVER_PATH_UNSAFE'
      )
      const identityDirectory = deriveDirectChildPath(serverDirectory, IDENTITY_DIRECTORY_NAME)
      const identityRealPath = await inspectDirectChildDirectory(
        identityDirectory,
        serverRealPath,
        IDENTITY_DIRECTORY_NAME,
        'SERVER_IDENTITY_PATH_UNSAFE'
      )
      const privateKeyPath = deriveDirectChildPath(identityDirectory, PRIVATE_KEY_FILE_NAME)
      const encryptedPrivateKey = await readRegularFile(
        privateKeyPath,
        identityRealPath,
        PRIVATE_KEY_FILE_NAME,
        MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
        'SERVER_IDENTITY_CORRUPTED',
        'SERVER_IDENTITY_PATH_UNSAFE'
      )

      let privateKeyBase64: string
      let privateKeyDer: Buffer | undefined
      try {
        privateKeyBase64 = secureStorage.decryptString(encryptedPrivateKey)
        privateKeyDer = Buffer.from(privateKeyBase64, 'base64')
        const serverPrivateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' })
        const invite = createServerInvite(server.serverId, serverPrivateKey, ownerDeviceIdentity, options)

        const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
        const db = openServerDatabase(databasePath, {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        })

        try {
          registerIssuedInvite(db, invite)
        } finally {
          db.close()
        }

        const encoded = encodeServerInvite(invite)
        return { invite, encoded }
      } catch (error) {
        if (error instanceof ServerInviteError) {
          throw new LocalServerStorageError(error.code)
        }

        if (error instanceof ServerDatabaseError) {
          throw new LocalServerStorageError(error.code)
        }

        if (error instanceof LocalServerStorageError) {
          throw error
        }

        throw new LocalServerStorageError('SERVER_INVITE_CREATION_FAILED')
      } finally {
        privateKeyDer?.fill(0)
      }
    },

    consumeLocalServerInvite: async (
      localStorageId: string,
      inviteOrEncoded: ServerInvite | string,
      options: { nowSeconds?: number } = {}
    ): Promise<void> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(databasePath, {
        deviceFingerprint: server.initialOwner.deviceFingerprint,
        publicKey: server.initialOwner.publicKey
      })

      try {
        consumeServerInvite(db, inviteOrEncoded, server.identity.publicKey, options)
      } catch (error) {
        if (error instanceof ServerDatabaseError) {
          throw new LocalServerStorageError(error.code)
        }
        if (error instanceof ServerInviteError) {
          throw new LocalServerStorageError(error.code)
        }
        throw new LocalServerStorageError('SERVER_DATABASE_CORRUPTED')
      } finally {
        db.close()
      }
    },

    revokeLocalServerInvite: async (
      localStorageId: string,
      inviteId: string
    ): Promise<void> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      if (
        server.initialOwner.deviceFingerprint !== ownerDeviceIdentity.fingerprint ||
        !server.initialOwner.publicKey.equals(ownerDeviceIdentity.publicKey)
      ) {
        throw new LocalServerStorageError('SERVER_INVITE_UNAUTHORIZED')
      }

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(databasePath, {
        deviceFingerprint: server.initialOwner.deviceFingerprint,
        publicKey: server.initialOwner.publicKey
      })

      try {
        revokeServerInvite(db, inviteId)
      } catch (error) {
        if (error instanceof ServerDatabaseError) {
          throw new LocalServerStorageError(error.code)
        }
        throw new LocalServerStorageError('SERVER_DATABASE_CORRUPTED')
      } finally {
        db.close()
      }
    },

    getStoredInvite: async (
      localStorageId: string,
      inviteId: string,
      nowSeconds?: number
    ): Promise<StoredInvite | undefined> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(databasePath, {
        deviceFingerprint: server.initialOwner.deviceFingerprint,
        publicKey: server.initialOwner.publicKey
      })

      try {
        return getStoredInvite(db, inviteId, nowSeconds)
      } finally {
        db.close()
      }
    },

    admitLocalServerMemberWithInvite: async (
      localStorageId: string,
      inviteOrEncoded: ServerInvite | string,
      candidateDevice: AuthenticatedCandidateDevice,
      options: { nowSeconds?: number } = {}
    ): Promise<Member> => {
      assertValidStorageId(localStorageId)
      assertServerIdentitySecureStorageAvailable(secureStorage, platform)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const serverRealPath = await inspectDirectChildDirectory(
        serverDirectory,
        rootRealPath,
        localStorageId,
        'SERVER_PATH_UNSAFE'
      )
      const identityDirectory = deriveDirectChildPath(serverDirectory, IDENTITY_DIRECTORY_NAME)
      const identityRealPath = await inspectDirectChildDirectory(
        identityDirectory,
        serverRealPath,
        IDENTITY_DIRECTORY_NAME,
        'SERVER_IDENTITY_PATH_UNSAFE'
      )
      const privateKeyPath = deriveDirectChildPath(identityDirectory, PRIVATE_KEY_FILE_NAME)
      const encryptedPrivateKey = await readRegularFile(
        privateKeyPath,
        identityRealPath,
        PRIVATE_KEY_FILE_NAME,
        MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
        'SERVER_IDENTITY_CORRUPTED',
        'SERVER_IDENTITY_PATH_UNSAFE'
      )

      let privateKeyBase64: string
      let privateKeyDer: Buffer | undefined
      try {
        privateKeyBase64 = secureStorage.decryptString(encryptedPrivateKey)
        privateKeyDer = Buffer.from(privateKeyBase64, 'base64')
        const serverPrivateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' })

        const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
        const db = openServerDatabase(
          databasePath,
          {
            deviceFingerprint: server.initialOwner.deviceFingerprint,
            publicKey: server.initialOwner.publicKey
          },
          {
            serverId: server.serverId,
            serverPublicKey: server.identity.publicKey
          }
        )

        try {
          return admitMemberWithInvite(
            db,
            inviteOrEncoded,
            candidateDevice,
            server.serverId,
            server.identity.publicKey,
            serverPrivateKey,
            options
          )
        } finally {
          db.close()
        }
      } catch (error) {
        if (error instanceof ServerDatabaseError) {
          throw new LocalServerStorageError(error.code)
        }
        if (error instanceof ServerInviteError) {
          throw new LocalServerStorageError(error.code)
        }
        if (error instanceof LocalServerStorageError) {
          throw error
        }
        throw new LocalServerStorageError('SERVER_ADMISSION_FAILED')
      } finally {
        if (privateKeyDer) {
          privateKeyDer.fill(0)
        }
      }
    },

    verifyLocalServerMemberAuthorization: async (
      localStorageId: string,
      targetFingerprint: string
    ): Promise<VerifiedMemberAuthorization> => {
      assertValidStorageId(localStorageId)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )

      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(
        databasePath,
        {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        },
        {
          serverId: server.serverId,
          serverPublicKey: server.identity.publicKey
        }
      )

      try {
        return verifyPersistedMemberAuthorization(
          db,
          server.serverId,
          server.identity.publicKey,
          {
            deviceFingerprint: server.initialOwner.deviceFingerprint,
            publicKey: server.initialOwner.publicKey
          },
          targetFingerprint
        )
      } finally {
        db.close()
      }
    },

    createLocalServerChannel: async (
      localStorageId: string,
      options: { readonly name: string; readonly actorFingerprint: string; readonly nowSeconds?: number }
    ): Promise<ServerChannel> => {
      const channel = await mutateChannelTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        createChannel(db, {
          name: options.name,
          actorFingerprint: options.actorFingerprint,
          isOwner: authorization.isOwner,
          nowSeconds: options.nowSeconds
        })
      )
      return channel!
    },

    renameLocalServerChannel: async (
      localStorageId: string,
      options: { readonly channelId: string; readonly name: string; readonly actorFingerprint: string }
    ): Promise<ServerChannel> => {
      const channel = await mutateChannelTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        renameChannel(db, {
          channelId: options.channelId,
          name: options.name,
          actorFingerprint: options.actorFingerprint,
          isOwner: authorization.isOwner
        })
      )
      return channel!
    },

    setLocalServerChannelArchived: async (
      localStorageId: string,
      options: { readonly channelId: string; readonly archived: boolean; readonly actorFingerprint: string }
    ): Promise<ServerChannel> => {
      const channel = await mutateChannelTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        setChannelArchived(db, {
          channelId: options.channelId,
          archived: options.archived,
          actorFingerprint: options.actorFingerprint,
          isOwner: authorization.isOwner
        })
      )
      return channel!
    },

    deleteLocalServerChannel: async (
      localStorageId: string,
      options: { readonly channelId: string; readonly actorFingerprint: string }
    ): Promise<void> => {
      await mutateChannelTable(localStorageId, options.actorFingerprint, (db, authorization) => {
        deleteChannel(db, {
          channelId: options.channelId,
          actorFingerprint: options.actorFingerprint,
          isOwner: authorization.isOwner
        })
      })
    },

    listLocalServerChannels: async (
      localStorageId: string
    ): Promise<readonly ServerChannel[]> => {
      assertValidStorageId(localStorageId)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )
      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(
        databasePath,
        {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        },
        {
          serverId: server.serverId,
          serverPublicKey: server.identity.publicKey
        }
      )

      try {
        return Object.freeze(listChannels(db))
      } finally {
        db.close()
      }
    },

    createLocalServerMessage: async (
      localStorageId: string,
      options: {
        readonly channelId: string
        readonly content: string
        readonly clientMessageId: string
        readonly actorFingerprint: string
        readonly nowSeconds?: number
      }
    ): Promise<ServerMessage> => {
      const message = await mutateMessageTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        createMessage(db, {
          channelId: options.channelId,
          content: options.content,
          clientMessageId: options.clientMessageId,
          authorization: createMessageOperationAuthorization({
            actorFingerprint: options.actorFingerprint,
            isAuthorized: authorization.isAuthorized,
            isOwner: authorization.isOwner
          }),
          nowSeconds: options.nowSeconds
        })
      )
      return message!
    },

    editLocalServerMessage: async (
      localStorageId: string,
      options: {
        readonly messageId: string
        readonly content: string
        readonly actorFingerprint: string
        readonly nowSeconds?: number
      }
    ): Promise<ServerMessage> => {
      const message = await mutateMessageTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        editMessage(db, {
          messageId: options.messageId,
          content: options.content,
          authorization: createMessageOperationAuthorization({
            actorFingerprint: options.actorFingerprint,
            isAuthorized: authorization.isAuthorized,
            isOwner: authorization.isOwner
          }),
          nowSeconds: options.nowSeconds
        })
      )
      return message!
    },

    deleteLocalServerMessage: async (
      localStorageId: string,
      options: {
        readonly messageId: string
        readonly actorFingerprint: string
        readonly nowSeconds?: number
      }
    ): Promise<ServerMessage> => {
      const message = await mutateMessageTable(localStorageId, options.actorFingerprint, (db, authorization) =>
        deleteMessage(db, {
          messageId: options.messageId,
          authorization: createMessageOperationAuthorization({
            actorFingerprint: options.actorFingerprint,
            isAuthorized: authorization.isAuthorized,
            isOwner: authorization.isOwner
          }),
          nowSeconds: options.nowSeconds
        })
      )
      return message!
    },

    listLocalServerMessages: async (
      localStorageId: string,
      options: {
        readonly channelId: string
        readonly afterSequence?: number
        readonly limit?: number
      }
    ): Promise<readonly ServerMessage[]> => {
      assertValidStorageId(localStorageId)
      const rootRealPath = await inspectServersRoot(serversRoot)

      if (!rootRealPath) {
        throw new LocalServerStorageError('SERVER_NOT_FOUND')
      }

      const server = await loadLocalServerFromRoot(
        serversRoot,
        rootRealPath,
        localStorageId,
        secureStorage,
        platform
      )
      const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
      const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
      const db = openServerDatabase(
        databasePath,
        {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        },
        {
          serverId: server.serverId,
          serverPublicKey: server.identity.publicKey
        }
      )

      try {
        return Object.freeze(listMessages(db, options))
      } finally {
        db.close()
      }
    }
  })

  /**
   * Owner-only channel mutations. The actor fingerprint is an authenticated fact from
   * the outer connection; ownership is revalidated against persisted state on every call.
   */
  async function mutateChannelTable(
    localStorageId: string,
    actorFingerprint: string,
    operation: (db: DatabaseSync, authorization: VerifiedMemberAuthorization) => void | ServerChannel
  ): Promise<ServerChannel | undefined> {
    assertValidStorageId(localStorageId)
    assertServerIdentitySecureStorageAvailable(secureStorage, platform)
    const rootRealPath = await inspectServersRoot(serversRoot)

    if (!rootRealPath) {
      throw new LocalServerStorageError('SERVER_NOT_FOUND')
    }

    const server = await loadLocalServerFromRoot(
      serversRoot,
      rootRealPath,
      localStorageId,
      secureStorage,
      platform
    )
    const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
    const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
    const db = openServerDatabase(
      databasePath,
      {
        deviceFingerprint: server.initialOwner.deviceFingerprint,
        publicKey: server.initialOwner.publicKey
      },
      {
        serverId: server.serverId,
        serverPublicKey: server.identity.publicKey
      }
    )

    try {
      const authorization = verifyPersistedMemberAuthorization(
        db,
        server.serverId,
        server.identity.publicKey,
        {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        },
        actorFingerprint
      )
      const result = operation(db, authorization)
      return result === undefined ? undefined : result
    } finally {
      db.close()
    }
  }

  /**
   * Authorized-member message mutations. The actor fingerprint is an authenticated
   * fact from the outer connection; authorization is revalidated on every call.
   */
  async function mutateMessageTable(
    localStorageId: string,
    actorFingerprint: string,
    operation: (db: DatabaseSync, authorization: VerifiedMemberAuthorization) => ServerMessage
  ): Promise<ServerMessage | undefined> {
    assertValidStorageId(localStorageId)
    assertServerIdentitySecureStorageAvailable(secureStorage, platform)
    const rootRealPath = await inspectServersRoot(serversRoot)

    if (!rootRealPath) {
      throw new LocalServerStorageError('SERVER_NOT_FOUND')
    }

    const server = await loadLocalServerFromRoot(
      serversRoot,
      rootRealPath,
      localStorageId,
      secureStorage,
      platform
    )
    const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
    const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
    const db = openServerDatabase(
      databasePath,
      {
        deviceFingerprint: server.initialOwner.deviceFingerprint,
        publicKey: server.initialOwner.publicKey
      },
      {
        serverId: server.serverId,
        serverPublicKey: server.identity.publicKey
      }
    )

    try {
      const authorization = verifyPersistedMemberAuthorization(
        db,
        server.serverId,
        server.identity.publicKey,
        {
          deviceFingerprint: server.initialOwner.deviceFingerprint,
          publicKey: server.initialOwner.publicKey
        },
        actorFingerprint
      )
      return operation(db, authorization)
    } finally {
      db.close()
    }
  }
}

function deriveServersRoot(userDataDirectory: string): string {
  if (
    typeof userDataDirectory !== 'string' ||
    !isAbsolute(userDataDirectory) ||
    resolve(userDataDirectory) !== userDataDirectory
  ) {
    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  return deriveDirectChildPath(userDataDirectory, SERVERS_DIRECTORY_NAME)
}

function generateLocalStorageId(): string {
  return randomBytes(16).toString('hex')
}

async function ensureServersRoot(serversRoot: string): Promise<string> {
  try {
    await mkdir(serversRoot, { mode: 0o700 })
  } catch (error) {
    if (!isErrorWithCode(error) || error.code !== 'EEXIST') {
      throw new LocalServerStorageError('SERVER_CREATION_FAILED')
    }
  }

  const inspectedRoot = await inspectServersRoot(serversRoot)

  if (!inspectedRoot) {
    throw new LocalServerStorageError('SERVER_CREATION_FAILED')
  }

  return inspectedRoot
}

async function inspectServersRoot(serversRoot: string): Promise<string | undefined> {
  let rootStats: Awaited<ReturnType<typeof lstat>>

  try {
    rootStats = await lstat(serversRoot)
  } catch (error) {
    if (isErrorWithCode(error) && error.code === 'ENOENT') {
      return undefined
    }

    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  try {
    return await realpath(serversRoot)
  } catch {
    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }
}

async function tryCreateLocalServer(
  serversRoot: string,
  rootRealPath: string,
  localStorageId: string,
  displayName: string,
  identityMaterial: ServerIdentityMaterial,
  ownerDeviceIdentity: InitialOwnerDeviceIdentity,
  secureStorage: ServerIdentitySafeStorage,
  platform: NodeJS.Platform
): Promise<LocalServer | undefined> {
  const finalDirectory = deriveDirectChildPath(serversRoot, localStorageId)
  const stagingName = `.creating-${localStorageId}-${randomBytes(8).toString('hex')}`
  const stagingDirectory = deriveDirectChildPath(serversRoot, stagingName)
  const stagedMetadataPath = deriveDirectChildPath(stagingDirectory, METADATA_FILE_NAME)
  const stagedIdentityDirectory = deriveDirectChildPath(stagingDirectory, IDENTITY_DIRECTORY_NAME)
  const stagedIdentityMetadataPath = deriveDirectChildPath(
    stagedIdentityDirectory,
    IDENTITY_METADATA_FILE_NAME
  )
  const stagedPrivateKeyPath = deriveDirectChildPath(
    stagedIdentityDirectory,
    PRIVATE_KEY_FILE_NAME
  )
  const stagedAuthorityDirectory = deriveDirectChildPath(
    stagingDirectory,
    AUTHORITY_DIRECTORY_NAME
  )
  const stagedOwnerMetadataPath = deriveDirectChildPath(
    stagedAuthorityDirectory,
    OWNER_METADATA_FILE_NAME
  )
  const stagedDatabasePath = deriveDirectChildPath(stagingDirectory, DATABASE_FILE_NAME)
  const finalMetadataPath = deriveDirectChildPath(finalDirectory, METADATA_FILE_NAME)
  const finalIdentityDirectory = deriveDirectChildPath(finalDirectory, IDENTITY_DIRECTORY_NAME)
  const finalIdentityMetadataPath = deriveDirectChildPath(
    finalIdentityDirectory,
    IDENTITY_METADATA_FILE_NAME
  )
  const finalPrivateKeyPath = deriveDirectChildPath(finalIdentityDirectory, PRIVATE_KEY_FILE_NAME)
  const finalAuthorityDirectory = deriveDirectChildPath(
    finalDirectory,
    AUTHORITY_DIRECTORY_NAME
  )
  const finalOwnerMetadataPath = deriveDirectChildPath(
    finalAuthorityDirectory,
    OWNER_METADATA_FILE_NAME
  )
  const finalDatabasePath = deriveDirectChildPath(finalDirectory, DATABASE_FILE_NAME)
  const metadata = Object.freeze({
    version: SERVER_METADATA_VERSION,
    localStorageId,
    displayName,
    serverId: identityMaterial.identity.serverId
  })
  let finalDirectoryReserved = false
  let finalIdentityDirectoryReserved = false
  let finalAuthorityDirectoryReserved = false
  let identityMetadataPublished = false
  let privateKeyPublished = false
  let ownerMetadataPublished = false
  let databasePublished = false
  let metadataPublished = false

  try {
    await mkdir(stagingDirectory, { mode: 0o700 })
    await mkdir(stagedIdentityDirectory, { mode: 0o700 })
    await mkdir(stagedAuthorityDirectory, { mode: 0o700 })
    await writeExclusiveFile(
      stagedIdentityMetadataPath,
      identityMaterial.metadataBytes,
      MAX_SERVER_IDENTITY_METADATA_BYTES
    )
    await writeExclusiveFile(
      stagedPrivateKeyPath,
      identityMaterial.encryptedPrivateKey,
      MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES
    )
    await writeExclusiveFile(
      stagedOwnerMetadataPath,
      identityMaterial.initialOwnerMetadataBytes,
      MAX_INITIAL_OWNER_METADATA_BYTES
    )
    await writeServerMetadata(stagedMetadataPath, metadata)
    initializeServerDatabase(stagedDatabasePath, ownerDeviceIdentity)
    await validateServerDatabaseFile(stagedDatabasePath, {
      deviceFingerprint: ownerDeviceIdentity.fingerprint,
      publicKey: ownerDeviceIdentity.publicKey
    })

    const validatedIdentity = loadServerIdentity(
      identityMaterial.metadataBytes,
      identityMaterial.encryptedPrivateKey,
      secureStorage,
      platform
    )

    if (validatedIdentity.serverId !== metadata.serverId) {
      throw new LocalServerStorageError('SERVER_IDENTITY_ID_MISMATCH')
    }

    const validatedOwner = loadInitialOwnerBinding(
      identityMaterial.initialOwnerMetadataBytes,
      validatedIdentity.serverId,
      validatedIdentity.publicKey
    )

    if (
      validatedOwner.deviceFingerprint !== ownerDeviceIdentity.fingerprint ||
      !validatedOwner.publicKey.equals(ownerDeviceIdentity.publicKey)
    ) {
      throw new LocalServerStorageError('SERVER_OWNER_BINDING_INVALID')
    }

    try {
      await mkdir(finalDirectory, { mode: 0o700 })
      finalDirectoryReserved = true
    } catch (error) {
      if (isErrorWithCode(error) && error.code === 'EEXIST') {
        await removeStagingDirectory(stagingDirectory)
        return undefined
      }

      throw error
    }

    const finalRealPath = await inspectDirectChildDirectory(
      finalDirectory,
      rootRealPath,
      localStorageId,
      'SERVER_PATH_UNSAFE'
    )
    await mkdir(finalIdentityDirectory, { mode: 0o700 })
    finalIdentityDirectoryReserved = true
    await inspectDirectChildDirectory(
      finalIdentityDirectory,
      finalRealPath,
      IDENTITY_DIRECTORY_NAME,
      'SERVER_IDENTITY_PATH_UNSAFE'
    )
    await mkdir(finalAuthorityDirectory, { mode: 0o700 })
    finalAuthorityDirectoryReserved = true
    await inspectDirectChildDirectory(
      finalAuthorityDirectory,
      finalRealPath,
      AUTHORITY_DIRECTORY_NAME,
      'SERVER_OWNER_BINDING_PATH_UNSAFE'
    )

    // server.json é o commit lógico e é publicado por último. Hard links falham se
    // o destino já existir, evitando o overwrite possível com rename em alguns sistemas.
    await link(stagedIdentityMetadataPath, finalIdentityMetadataPath)
    identityMetadataPublished = true
    await link(stagedPrivateKeyPath, finalPrivateKeyPath)
    privateKeyPublished = true
    await link(stagedOwnerMetadataPath, finalOwnerMetadataPath)
    ownerMetadataPublished = true
    await link(stagedDatabasePath, finalDatabasePath)
    databasePublished = true
    await link(stagedMetadataPath, finalMetadataPath)
    metadataPublished = true

    await removeStagingDirectory(stagingDirectory)
    return createLocalServer(metadata, validatedIdentity, validatedOwner)
  } catch (error) {
    await removeStagingDirectory(stagingDirectory)

    if (finalDirectoryReserved && !metadataPublished) {
      if (databasePublished) {
        await unlink(finalDatabasePath).catch(() => undefined)
      }

      if (ownerMetadataPublished) {
        await unlink(finalOwnerMetadataPath).catch(() => undefined)
      }

      if (privateKeyPublished) {
        await unlink(finalPrivateKeyPath).catch(() => undefined)
      }

      if (identityMetadataPublished) {
        await unlink(finalIdentityMetadataPath).catch(() => undefined)
      }

      if (finalIdentityDirectoryReserved) {
        await rmdir(finalIdentityDirectory).catch(() => undefined)
      }

      if (finalAuthorityDirectoryReserved) {
        await rmdir(finalAuthorityDirectory).catch(() => undefined)
      }

      await rmdir(finalDirectory).catch(() => undefined)
    }

    if (
      error instanceof LocalServerStorageError ||
      error instanceof ServerIdentityError ||
      error instanceof InitialOwnerBindingError ||
      error instanceof ServerDatabaseError
    ) {
      if (error instanceof ServerDatabaseError) {
        throw new LocalServerStorageError(error.code)
      }

      throw error
    }

    throw new LocalServerStorageError('SERVER_CREATION_FAILED')
  }
}

async function writeServerMetadata(
  metadataPath: string,
  metadata: LocalServerMetadata
): Promise<void> {
  const contents = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8')
  await writeExclusiveFile(metadataPath, contents, MAX_SERVER_METADATA_BYTES)
}

async function writeExclusiveFile(
  filePath: string,
  contents: Buffer,
  maximumBytes: number
): Promise<void> {
  let fileHandle: Awaited<ReturnType<typeof open>> | undefined

  if (contents.length === 0 || contents.length > maximumBytes) {
    throw new LocalServerStorageError('SERVER_CREATION_FAILED')
  }

  try {
    fileHandle = await open(filePath, 'wx', 0o600)
    await fileHandle.writeFile(contents)
    await fileHandle.sync()
    await fileHandle.close()
    fileHandle = undefined
  } catch {
    if (fileHandle) {
      await fileHandle.close().catch(() => undefined)
    }

    throw new LocalServerStorageError('SERVER_CREATION_FAILED')
  }
}

async function loadLocalServerFromRoot(
  serversRoot: string,
  rootRealPath: string,
  localStorageId: string,
  secureStorage: ServerIdentitySafeStorage,
  platform: NodeJS.Platform
): Promise<LocalServer> {
  const serverDirectory = deriveDirectChildPath(serversRoot, localStorageId)
  let serverStats: Awaited<ReturnType<typeof lstat>>

  try {
    serverStats = await lstat(serverDirectory)
  } catch (error) {
    if (isErrorWithCode(error) && error.code === 'ENOENT') {
      throw new LocalServerStorageError('SERVER_NOT_FOUND')
    }

    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  if (!serverStats.isDirectory() || serverStats.isSymbolicLink()) {
    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  const serverRealPath = await inspectDirectChildDirectory(
    serverDirectory,
    rootRealPath,
    localStorageId,
    'SERVER_PATH_UNSAFE'
  )
  const metadataPath = deriveDirectChildPath(serverDirectory, METADATA_FILE_NAME)
  const metadataBytes = await readRegularFile(
    metadataPath,
    serverRealPath,
    METADATA_FILE_NAME,
    MAX_SERVER_METADATA_BYTES,
    'SERVER_METADATA_CORRUPTED',
    'SERVER_PATH_UNSAFE'
  )
  const metadata = parseMetadata(metadataBytes, localStorageId)
  const identityDirectory = deriveDirectChildPath(serverDirectory, IDENTITY_DIRECTORY_NAME)
  const identityRealPath = await inspectDirectChildDirectory(
    identityDirectory,
    serverRealPath,
    IDENTITY_DIRECTORY_NAME,
    'SERVER_IDENTITY_PATH_UNSAFE'
  )
  const identityMetadataPath = deriveDirectChildPath(
    identityDirectory,
    IDENTITY_METADATA_FILE_NAME
  )
  const privateKeyPath = deriveDirectChildPath(identityDirectory, PRIVATE_KEY_FILE_NAME)
  const identityMetadataBytes = await readRegularFile(
    identityMetadataPath,
    identityRealPath,
    IDENTITY_METADATA_FILE_NAME,
    MAX_SERVER_IDENTITY_METADATA_BYTES,
    'SERVER_IDENTITY_CORRUPTED',
    'SERVER_IDENTITY_PATH_UNSAFE'
  )
  const encryptedPrivateKey = await readRegularFile(
    privateKeyPath,
    identityRealPath,
    PRIVATE_KEY_FILE_NAME,
    MAX_SERVER_ENCRYPTED_PRIVATE_KEY_BYTES,
    'SERVER_IDENTITY_CORRUPTED',
    'SERVER_IDENTITY_PATH_UNSAFE'
  )
  const identity = loadServerIdentity(
    identityMetadataBytes,
    encryptedPrivateKey,
    secureStorage,
    platform
  )

  if (metadata.serverId !== identity.serverId) {
    throw new LocalServerStorageError('SERVER_IDENTITY_ID_MISMATCH')
  }

  const authorityDirectory = deriveDirectChildPath(serverDirectory, AUTHORITY_DIRECTORY_NAME)
  const authorityRealPath = await inspectDirectChildDirectory(
    authorityDirectory,
    serverRealPath,
    AUTHORITY_DIRECTORY_NAME,
    'SERVER_OWNER_BINDING_PATH_UNSAFE'
  )
  const ownerMetadataPath = deriveDirectChildPath(
    authorityDirectory,
    OWNER_METADATA_FILE_NAME
  )
  const ownerMetadataBytes = await readRegularFile(
    ownerMetadataPath,
    authorityRealPath,
    OWNER_METADATA_FILE_NAME,
    MAX_INITIAL_OWNER_METADATA_BYTES,
    'SERVER_OWNER_BINDING_INVALID',
    'SERVER_OWNER_BINDING_PATH_UNSAFE'
  )
  const initialOwner = loadInitialOwnerBinding(
    ownerMetadataBytes,
    identity.serverId,
    identity.publicKey
  )

  const databasePath = deriveDirectChildPath(serverDirectory, DATABASE_FILE_NAME)
  let databaseStats: Awaited<ReturnType<typeof lstat>>

  try {
    databaseStats = await lstat(databasePath)
  } catch (error) {
    if (isErrorWithCode(error) && error.code === 'ENOENT') {
      throw new LocalServerStorageError('SERVER_DATABASE_NOT_FOUND')
    }

    throw new LocalServerStorageError('SERVER_DATABASE_PATH_UNSAFE')
  }

  if (databaseStats.isSymbolicLink() || !databaseStats.isFile()) {
    throw new LocalServerStorageError('SERVER_DATABASE_PATH_UNSAFE')
  }

  try {
    const databaseRealPath = await realpath(databasePath)
    assertDirectRealChild(
      databaseRealPath,
      serverRealPath,
      DATABASE_FILE_NAME,
      'SERVER_DATABASE_PATH_UNSAFE'
    )
  } catch (error) {
    if (error instanceof LocalServerStorageError) {
      throw error
    }

    throw new LocalServerStorageError('SERVER_DATABASE_PATH_UNSAFE')
  }

  try {
    await validateServerDatabaseFile(
      databasePath,
      {
        deviceFingerprint: initialOwner.deviceFingerprint,
        publicKey: initialOwner.publicKey
      },
      {
        serverId: identity.serverId,
        serverPublicKey: identity.publicKey
      }
    )
  } catch (error) {
    if (error instanceof ServerDatabaseError) {
      throw new LocalServerStorageError(error.code)
    }

    throw new LocalServerStorageError('SERVER_DATABASE_CORRUPTED')
  }

  return createLocalServer(metadata, identity, initialOwner)
}

async function inspectDirectChildDirectory(
  directoryPath: string,
  parentRealPath: string,
  expectedName: string,
  unsafeCode: Extract<
    LocalServerStorageErrorCode,
    | 'SERVER_PATH_UNSAFE'
    | 'SERVER_IDENTITY_PATH_UNSAFE'
    | 'SERVER_OWNER_BINDING_PATH_UNSAFE'
  >
): Promise<string> {
  try {
    const directoryStats = await lstat(directoryPath)

    if (!directoryStats.isDirectory() || directoryStats.isSymbolicLink()) {
      throw new LocalServerStorageError(unsafeCode)
    }

    const directoryRealPath = await realpath(directoryPath)
    assertDirectRealChild(directoryRealPath, parentRealPath, expectedName, unsafeCode)
    return directoryRealPath
  } catch (error) {
    if (error instanceof LocalServerStorageError) {
      throw error
    }

    throw new LocalServerStorageError(unsafeCode)
  }
}

async function readRegularFile(
  filePath: string,
  parentRealPath: string,
  expectedName: string,
  maximumBytes: number,
  corruptedCode: Extract<
    LocalServerStorageErrorCode,
    | 'SERVER_METADATA_CORRUPTED'
    | 'SERVER_IDENTITY_CORRUPTED'
    | 'SERVER_OWNER_BINDING_INVALID'
  >,
  unsafeCode: Extract<
    LocalServerStorageErrorCode,
    | 'SERVER_PATH_UNSAFE'
    | 'SERVER_IDENTITY_PATH_UNSAFE'
    | 'SERVER_OWNER_BINDING_PATH_UNSAFE'
  >
): Promise<Buffer> {
  try {
    const fileStats = await lstat(filePath)

    if (fileStats.isSymbolicLink()) {
      throw new LocalServerStorageError(unsafeCode)
    }

    if (!fileStats.isFile() || fileStats.size === 0 || fileStats.size > maximumBytes) {
      throw new LocalServerStorageError(corruptedCode)
    }

    const fileRealPath = await realpath(filePath)
    assertDirectRealChild(fileRealPath, parentRealPath, expectedName, unsafeCode)
    const contents = await readFile(filePath)

    if (contents.length === 0 || contents.length > maximumBytes) {
      throw new LocalServerStorageError(corruptedCode)
    }

    return contents
  } catch (error) {
    if (error instanceof LocalServerStorageError) {
      throw error
    }

    throw new LocalServerStorageError(corruptedCode)
  }
}

function parseMetadata(metadataBytes: Buffer, expectedStorageId: string): LocalServerMetadata {
  let value: unknown

  try {
    value = JSON.parse(metadataBytes.toString('utf8'))
  } catch {
    throw new LocalServerStorageError('SERVER_METADATA_CORRUPTED')
  }

  if (!isRecord(value)) {
    throw new LocalServerStorageError('SERVER_METADATA_CORRUPTED')
  }

  if (value.version !== SERVER_METADATA_VERSION) {
    if (typeof value.version === 'number' && Number.isInteger(value.version)) {
      throw new LocalServerStorageError('SERVER_VERSION_UNSUPPORTED')
    }

    throw new LocalServerStorageError('SERVER_METADATA_CORRUPTED')
  }

  const expectedKeys = ['displayName', 'localStorageId', 'serverId', 'version']

  if (
    Object.keys(value).sort().join(',') !== expectedKeys.join(',') ||
    typeof value.localStorageId !== 'string' ||
    value.localStorageId !== expectedStorageId ||
    !isValidStorageId(value.localStorageId) ||
    typeof value.displayName !== 'string' ||
    !isValidServerId(value.serverId)
  ) {
    throw new LocalServerStorageError('SERVER_METADATA_CORRUPTED')
  }

  try {
    assertValidDisplayName(value.displayName)
  } catch {
    throw new LocalServerStorageError('SERVER_METADATA_CORRUPTED')
  }

  return Object.freeze({
    version: SERVER_METADATA_VERSION,
    localStorageId: value.localStorageId,
    displayName: value.displayName,
    serverId: value.serverId
  })
}

function createLocalServer(
  metadata: LocalServerMetadata,
  identity: ServerIdentity,
  initialOwner: InitialOwnerBinding
): LocalServer {
  return Object.freeze({ ...metadata, identity, initialOwner })
}

function assertValidDisplayName(value: unknown): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    !isWellFormedUnicode(value) ||
    value.normalize('NFC') !== value ||
    [...value].length > MAX_DISPLAY_NAME_CODE_POINTS ||
    /\p{Cc}/u.test(value)
  ) {
    throw new LocalServerStorageError('INVALID_SERVER_NAME')
  }
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)

    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const nextCodeUnit = value.charCodeAt(index + 1)

      if (nextCodeUnit < 0xdc00 || nextCodeUnit > 0xdfff) {
        return false
      }

      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false
    }
  }

  return true
}

function assertValidStorageId(value: unknown): asserts value is string {
  if (!isValidStorageId(value)) {
    throw new LocalServerStorageError('INVALID_STORAGE_ID')
  }
}

function isValidStorageId(value: unknown): value is string {
  return typeof value === 'string' && STORAGE_ID_PATTERN.test(value)
}

function deriveDirectChildPath(parentPath: string, childName: string): string {
  const childPath = resolve(parentPath, childName)
  const relativePath = relative(parentPath, childPath)

  if (
    relativePath !== childName ||
    isAbsolute(relativePath) ||
    relativePath === '..' ||
    relativePath.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`)
  ) {
    throw new LocalServerStorageError('SERVER_PATH_UNSAFE')
  }

  return childPath
}

function assertDirectRealChild(
  childRealPath: string,
  parentRealPath: string,
  expectedName: string,
  unsafeCode: Extract<
    LocalServerStorageErrorCode,
    | 'SERVER_PATH_UNSAFE'
    | 'SERVER_IDENTITY_PATH_UNSAFE'
    | 'SERVER_OWNER_BINDING_PATH_UNSAFE'
    | 'SERVER_DATABASE_PATH_UNSAFE'
  >
): void {
  if (
    !areSameFilesystemPath(dirname(childRealPath), parentRealPath) ||
    !areSameFilesystemPath(basename(childRealPath), expectedName)
  ) {
    throw new LocalServerStorageError(unsafeCode)
  }
}

function areSameFilesystemPath(firstPath: string, secondPath: string): boolean {
  if (process.platform === 'win32') {
    return firstPath.toLowerCase() === secondPath.toLowerCase()
  }

  return firstPath === secondPath
}

async function removeStagingDirectory(stagingDirectory: string): Promise<void> {
  await rm(stagingDirectory, { force: true, recursive: true }).catch(() => undefined)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isErrorWithCode(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error
}
