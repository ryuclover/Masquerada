import { isAuthorizedPeerChannel, type AuthorizedPeerChannel } from '../network/tcp-transport'
import type { LocalServerStorage } from '../servers/local-server-storage'
import { ApplicationEndpointError, type HistoryPage, createApplicationHost } from './application-endpoint'

/** Main-only adapter. Routing metadata and peer payloads never select a storage path. */
export async function attachLocalServerApplication(options: {
  readonly storage: LocalServerStorage
  readonly localStorageId: string
  readonly channel: AuthorizedPeerChannel
}): Promise<ReturnType<typeof createApplicationHost>> {
  const { storage, localStorageId, channel } = options
  if (!isAuthorizedPeerChannel(channel) || channel.isClosed()) {
    throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
  }
  const binding = channel.getAuthorizationBinding()
  if (!binding.serverId || !binding.peerDeviceFingerprint) {
    throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
  }
  const server = await storage.loadLocalServer(localStorageId)
  if (server.serverId !== binding.serverId || channel.isClosed()) {
    throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
  }

  return createApplicationHost({
    channel,
    serverId: server.serverId,
    authorizeServerStateRead: async (context, signal) => {
      signal.throwIfAborted()
      const current = await storage.loadLocalServer(localStorageId)
      signal.throwIfAborted()
      if (current.serverId !== context.serverId) {
        throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
      }
      const authorization = await storage.verifyLocalServerMemberAuthorization(
        localStorageId, context.peerDeviceFingerprint
      )
      signal.throwIfAborted()
      if (!authorization.isAuthorized) {
        throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
      }
    },
    readServerState: async (context, signal) => {
      signal.throwIfAborted()
      const current = await storage.loadLocalServer(localStorageId)
      signal.throwIfAborted()
      if (current.serverId !== context.serverId) {
        throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
      }
      return { displayName: current.displayName, channels: [] }
    },
    readServerHistory: async (context, query, signal) => {
      signal.throwIfAborted()
      const current = await storage.loadLocalServer(localStorageId)
      signal.throwIfAborted()
      if (current.serverId !== context.serverId) {
        throw new ApplicationEndpointError('APPLICATION_NOT_AUTHORIZED')
      }
      const messages = await storage.listLocalServerMessages(localStorageId, {
        channelId: query.channelId,
        afterSequence: query.afterSequence,
        limit: query.limit
      })
      signal.throwIfAborted()
      const hasMore = messages.length === query.limit && messages.length > 0
      return {
        messages: messages.map((message) => ({
          sequence: message.sequence,
          messageId: message.messageId,
          authorFingerprint: message.authorFingerprint,
          content: message.content,
          createdAt: message.createdAt,
          editedAt: message.editedAt,
          deletedAt: message.deletedAt
        })),
        hasMore
      } satisfies HistoryPage
    }
  })
}
