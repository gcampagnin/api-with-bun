import { jwt } from '@elysiajs/jwt'
import Elysia, { t, type Static } from 'elysia'
import { env } from '../env'
import { cookie } from '@elysiajs/cookie'

const jwtPayload = t.Object({
  sub: t.String(),
  restaurantId: t.Optional(t.String()),
})

export const auth = new Elysia()
  .use(cookie())
  .use(
    jwt({
      secret: env.JWT_SECRET_KEY,
      schema: jwtPayload,
    }),
  )
  .derive({ as: 'scoped' }, ({ jwt, cookie }) => {
    return {
      signUser: async (payload: Static<typeof jwtPayload>) => {
        const token = await jwt.sign(payload)

        if (!cookie.auth) {
          throw new Error('Cookie is not found.')
        }

        cookie.auth.value = token
        cookie.auth.httpOnly = true
        cookie.auth.maxAge = 60 * 60 * 24 * 7 // 7 days
        cookie.auth.path = '/'
      },

      signOut: async () => {
        cookie.auth?.remove()
      },

      getCurrentUser: async () => {
        const token =
          typeof cookie?.auth?.value === 'string'
            ? cookie.auth.value
            : undefined
        const payload = await jwt.verify(token)

        if (!payload) {
          throw new Error('Unauthorized.')
        }

        return {
          userId: payload.sub,
          restauranteId: payload.restaurantId,
        }
      },
    }
  })
