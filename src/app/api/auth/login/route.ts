import { NextResponse } from 'next/server';
import { getSupabaseClient } from '@/lib/supabase';
import { signToken, setAdminAuthCookie } from '@/lib/auth';

export const runtime = 'nodejs';

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const email =
      typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
    const password =
      typeof body?.password === 'string' ? body.password : '';

    if (!email || !password) {
      return NextResponse.json(
        { error: 'البريد الإلكتروني وكلمة المرور مطلوبان' },
        { status: 400 }
      );
    }

    const supabase = getSupabaseClient();
    if (!supabase) {
      return NextResponse.json(
        { error: 'إعدادات تسجيل الدخول غير مكتملة على الخادم' },
        { status: 503 }
      );
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error || !data.user || !data.session) {
      return NextResponse.json(
        { error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' },
        { status: 401 }
      );
    }

    const authenticatedEmail = data.user.email?.trim().toLowerCase();
    const configuredAdminEmail = process.env.ADMIN_EMAIL?.trim().toLowerCase();
    const hasAdminRole = data.user.app_metadata?.role === 'admin';
    const isAllowedEmail =
      Boolean(configuredAdminEmail) &&
      authenticatedEmail === configuredAdminEmail;

    if (!authenticatedEmail || (!hasAdminRole && !isAllowedEmail)) {
      return NextResponse.json(
        { error: 'هذا الحساب لا يملك صلاحية دخول لوحة الإدارة' },
        { status: 403 }
      );
    }

    const token = await signToken({
      username: authenticatedEmail,
      userId: data.user.id,
      email: authenticatedEmail,
    });

    await setAdminAuthCookie(token);

    return NextResponse.json(
      { success: true, email: authenticatedEmail },
      { headers: { 'Cache-Control': 'no-store' } }
    );
  } catch (error) {
    console.error('Admin login error:', error);
    return NextResponse.json(
      { error: 'حدث خطأ أثناء تسجيل الدخول' },
      { status: 500 }
    );
  }
}
