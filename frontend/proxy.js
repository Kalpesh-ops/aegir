import { createServerClient } from '@supabase/ssr'
import { NextResponse } from 'next/server'

export async function proxy(req) {
  const res = NextResponse.next()
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return req.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => {
            res.cookies.set(name, value, options)
          })
        },
      },
    }
  )
  const { data: { user } } = await supabase.auth.getUser()

  const isAuth = !!user
  const isDashboard = req.nextUrl.pathname.startsWith('/dashboard')
  const isLogin = req.nextUrl.pathname === '/login'

  if (isDashboard && !isAuth) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  if (isLogin && isAuth) {
    return NextResponse.redirect(new URL('/dashboard', req.url))
  }
  return res
}

export const config = {
  matcher: ['/dashboard/:path*', '/login'],
}
