import Elysia, { t } from 'elysia'
import { db } from '../../db/connection'
import { auth } from '../auth'
import dayjs from 'dayjs'
import { authLinks } from '../../db/schema'
import { eq } from 'drizzle-orm'

export const authenticateFromLink = new Elysia().use(auth).get(
  '/auth-links/authenticate',
  async ({ query, jwt, cookie: { auth }, redirect: sendRedirect }) => {
    const { code, redirect } = query

    const authLinkFromCode = await db.query.authLinks.findFirst({
      where(fields, { eq }) {
        return eq(fields.code, code)
      },
    })

    if (!authLinkFromCode) {
      throw new Error('Auth link not found.')
    }

    const daysSinceAuthLinkWasCreated = dayjs().diff(
      authLinkFromCode.createdAt,
      'days',
    )

    if (daysSinceAuthLinkWasCreated > 7) {
      throw new Error('Auth link expired, please generate a new one.')
    }

    const managedRestaurante = await db.query.restaurants.findFirst({
      where(fields, { eq }) {
        return eq(fields.managerId, authLinkFromCode.userId)
      },
    })

    const token = await jwt.sign({
      sub: authLinkFromCode.userId,
      restaurantId: managedRestaurante?.id,
    })

    if (!auth) {
      throw new Error('Cookie is not found.')
    }

    auth.value = token
    auth.httpOnly = true
    auth.maxAge = 60 * 60 * 24 * 7 // 7 days
    auth.path = '/'

    await db.delete(authLinks).where(eq(authLinks.code, code))

    return sendRedirect(redirect)
  },
  {
    query: t.Object({
      code: t.String(),
      redirect: t.String(),
    }),
  },
)
