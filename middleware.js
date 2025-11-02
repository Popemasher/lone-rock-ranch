import { NextResponse } from 'next/server';

// Protect everything; to leave paths public, adjust matcher.
export const config = { matcher: ['/(.*)'] };

export default function middleware(req) {
  const user = process.env.BASIC_AUTH_USER;
  const pass = process.env.BASIC_AUTH_PASS;

  // Fail closed if envs missing
  if (!user || !pass) {
    return new NextResponse(
      'Authentication misconfigured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS.',
      { status: 500 }
    );
  }

  const header = req.headers.get('authorization') || '';

  // Expect: "Basic base64(user:pass)"
  if (header.startsWith('Basic ')) {
    const base64 = header.slice(6).trim();
    try {
      const decoded = atob(base64);              // Edge runtime has atob
      const i = decoded.indexOf(':');
      const u = decoded.slice(0, i);
      const p = decoded.slice(i + 1);
      if (u === user && p === pass) return NextResponse.next();
    } catch {
      // fall through to challenge
    }
  }

  // Challenge
  return new NextResponse('Authentication required', {
    status: 401,
    headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
  });
}
