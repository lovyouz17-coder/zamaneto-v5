# زمانتو V5.1 — اتصال Frontend + Backend + PostgreSQL

این نسخه بر اساس V5 فعلی پروژه ساخته شده است.

## تغییرات
- OTP از Frontend حذف و به API بک‌اند منتقل شد.
- Session token واقعی از PostgreSQL استفاده می‌شود.
- بعد از ورود، state از `/api/state` از PostgreSQL خوانده می‌شود.
- تغییرات task / habit / focus / timer / theme با sync تأخیری به PostgreSQL می‌روند.
- پروفایل با `/api/me` ذخیره می‌شود.
- Logout، session را در سرور invalidate می‌کند.
- Clear Data، state سرور را هم reset می‌کند.
- خطای duplicate `const btn` در resend timer اصلاح شد.
- تاریخ روز بر اساس timezone محلی محاسبه می‌شود.

## اجرا
1. PostgreSQL را اجرا کن.
2. `.env.example` را به `.env` تبدیل کن و `DATABASE_URL` را تنظیم کن.
3. schema را اجرا کن:
   `psql "$DATABASE_URL" -f database/schema.sql`
4. `npm install`
5. `npm start`
6. `http://localhost:3000`

## تست هسته
شماره → OTP → ورود → ساخت Task → Refresh → باقی ماندن Task → Logout → ورود مجدد → باقی ماندن Task.

در development، اگر backend در حالت production نباشد، کد OTP به صورت `devCode` برای تست برمی‌گردد. برای انتشار باید سرویس SMS واقعی متصل شود.
