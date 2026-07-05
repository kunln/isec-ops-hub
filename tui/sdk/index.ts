export * from "./client.js"
export * from "./server.js"

import { createFlocksClient } from "./client.js"
import { createFlocksServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createFlocks(options?: ServerOptions) {
  const server = await createFlocksServer({
    ...options,
  })

  const client = createFlocksClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
