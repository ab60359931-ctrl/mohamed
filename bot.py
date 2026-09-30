# ============================================================
# bot.py - Devils Will Rise Decrypter Bot
# ============================================================
import os
import json
from functools import wraps

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    filters, ContextTypes
)

import database as db
from decryptors import (
    DTDecryptor, HCDecryptorV1, HCDecryptorV2,
    EHIDecryptor, NPVTDecryptor, SSCDecryptor
)

# ============================================================
# ⚙️ الإعدادات - عدل هنا بس
# ============================================================
BOT_TOKEN = "ضع_التوكن_هنا"       # ضع توكن البوت من BotFather
ADMIN_ID = 123456789              # ضع الآيدي بتاعك هنا
CHANNEL = "@قناتك"                 # ضع يوزر قناتك
BOT_NAME = "Devils Will Rise Decrypter"

# ============================================================
# Decorator: لازم يكون أدمن
# ============================================================
def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if not db.is_admin(user_id) and user_id != ADMIN_ID:
            return  # ميردش خالص
        return await func(update, context)
    return wrapper


# ============================================================
# /start
# ============================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.register_user(user.id, user.username or "", user.first_name or "")

    # لو محظور
    if db.is_banned(user.id):
        await update.message.reply_text("🚫 أنت محظور من استخدام البوت.")
        return

    # لو البوت متوقف ومش أدمن
    if not db.get_bot_status() and not db.is_admin(user.id) and user.id != ADMIN_ID:
        await update.message.reply_text("⛔ البوت متوقف حاليًا. حاول لاحقًا.")
        return

    await update.message.reply_text(
        f"💀 *{BOT_NAME}*\n\n"
        f"أرسل لي أي ملف إعدادات أو رابط:\n"
        f"• Dark Tunnel (.dark)\n"
        f"• HTTP Custom (.hc) — قديم وجديد\n"
        f"• HTTP Injector (.ehi)\n"
        f"• NPV Tunnel (.npvt)\n"
        f"• SSC Custom (.ssc)\n\n"
        f"🔓 سأفك التشفير وأعرض كل التفاصيل!",
        parse_mode="Markdown"
    )


# ============================================================
# /admin - لوحة التحكم (للأدمن فقط)
# ============================================================
@admin_only
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_main_menu(update, context)


async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE, edit=False):
    status = "🟢 يعمل" if db.get_bot_status() else "🔴 متوقف"
    stats = db.get_stats()

    text = (
        f"👑 *لوحة تحكم الأدمن*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 *الإحصائيات:*\n"
        f"• حالة البوت: {status}\n"
        f"• عدد المستخدمين: `{stats.get('total_users', 0)}`\n"
        f"• عدد عمليات الفك: `{stats.get('total_decrypts', 0)}`\n"
        f"• عدد المحظورين: `{len(db.get_banned())}`\n"
        f"• عدد الأدمنز: `{len(db.get_admins())}`\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )

    keyboard = [
        [InlineKeyboardButton(
            "🔴 إيقاف البوت" if db.get_bot_status() else "🟢 تشغيل البوت",
            callback_data="toggle_bot"
        )],
        [InlineKeyboardButton("👥 المستخدمون", callback_data="list_users"),
         InlineKeyboardButton("🚫 المحظورون", callback_data="list_banned")],
        [InlineKeyboardButton("👑 الأدمنز", callback_data="list_admins"),
         InlineKeyboardButton("📊 إحصائيات تفصيلية", callback_data="stats")],
        [InlineKeyboardButton("🔄 تحديث", callback_data="refresh")]
    ]

    if edit and update.callback_query:
        await update.callback_query.edit_message_text(
            text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(
            text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
        )


# ============================================================
# Callback Handler
# ============================================================
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id

    if not db.is_admin(user_id) and user_id != ADMIN_ID:
        await query.answer("⛔ للأدمن فقط", show_alert=True)
        return

    await query.answer()
    data = query.data

    # تشغيل / إيقاف البوت
    if data == "toggle_bot":
        new_status = not db.get_bot_status()
        db.set_bot_status(new_status)
        await show_main_menu(update, context, edit=True)
        return

    # قائمة المستخدمين
    if data == "list_users":
        users = db.get_all_users()
        if not users:
            text = "📭 لا يوجد مستخدمون بعد."
        else:
            text = f"👥 *المستخدمون ({len(users)}):*\n━━━━━━━━━━━━━━━━━━━━\n"
            for i, (uid, info) in enumerate(list(users.items())[-30:], 1):
                name = info.get("first_name", "") or "بدون اسم"
                uname = f"@{info['username']}" if info.get("username") else "—"
                ban = "🚫" if str(uid) in [str(b) for b in db.get_banned()] else ""
                text += f"{i}. {ban} `{uid}` — {name} ({uname})\n"
            if len(users) > 30:
                text += f"\n_... عرض آخر 30 مستخدم فقط من {len(users)}_"
        kb = [[InlineKeyboardButton("🔙 رجوع", callback_data="refresh")]]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
        return

    # قائمة المحظورين
    if data == "list_banned":
        banned = db.get_banned()
        if not banned:
            text = "📭 لا يوجد محظورون."
        else:
            text = f"🚫 *المحظورون ({len(banned)}):*\n━━━━━━━━━━━━━━━━━━━━\n"
            for i, uid in enumerate(banned, 1):
                users = db.get_all_users()
                info = users.get(str(uid), {})
                name = info.get("first_name", "غير معروف")
                text += f"{i}. `{uid}` — {name}\n"
            text += "\n_استخدم_ `/unban <id>` _لفك الحظر_"
        kb = [[InlineKeyboardButton("🔙 رجوع", callback_data="refresh")]]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
        return

    # قائمة الأدمنز
    if data == "list_admins":
        admins = db.get_admins()
        text = f"👑 *الأدمنز ({len(admins)}):*\n━━━━━━━━━━━━━━━━━━━━\n"
        if not admins:
            text += "_لا يوجد أدمنز مسجلون في الداتا بيز._\n"
        for i, uid in enumerate(admins, 1):
            text += f"{i}. `{uid}`\n"
        text += f"\n*الأدمن الرئيسي:* `{ADMIN_ID}`"
        text += "\n\n_استخدم_ `/addadmin <id>` _أو_ `/deladmin <id>`"
        kb = [[InlineKeyboardButton("🔙 رجوع", callback_data="refresh")]]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
        return

    # إحصائيات تفصيلية
    if data == "stats":
        stats = db.get_stats()
        by_type = stats.get("decrypts_by_type", {})
        text = (
            f"📊 *إحصائيات تفصيلية*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"👥 إجمالي المستخدمين: `{stats.get('total_users', 0)}`\n"
            f"🔓 إجمالي عمليات الفك: `{stats.get('total_decrypts', 0)}`\n"
            f"🚫 المحظورون: `{len(db.get_banned())}`\n"
            f"👑 الأدمنز: `{len(db.get_admins())}`\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"*حسب النوع:*\n"
        )
        if by_type:
            for k, v in by_type.items():
                text += f"• {k}: `{v}`\n"
        else:
            text += "_لا يوجد بعد_"
        kb = [[InlineKeyboardButton("🔙 رجوع", callback_data="refresh")]]
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
        return

    # تحديث
    if data == "refresh":
        await show_main_menu(update, context, edit=True)
        return


# ============================================================
# أوامر الأدمن
# ============================================================
@admin_only
async def ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("الاستخدام: `/ban <user_id>`", parse_mode="Markdown")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ آيدي غير صحيح")
        return
    if db.ban_user(uid):
        await update.message.reply_text(f"✅ تم حظر المستخدم `{uid}`", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ المستخدم `{uid}` محظور بالفعل", parse_mode="Markdown")


@admin_only
async def unban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("الاستخدام: `/unban <user_id>`", parse_mode="Markdown")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ آيدي غير صحيح")
        return
    if db.unban_user(uid):
        await update.message.reply_text(f"✅ تم فك الحظر عن `{uid}`", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ المستخدم `{uid}` غير محظور", parse_mode="Markdown")


@admin_only
async def add_admin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("الاستخدام: `/addadmin <user_id>`", parse_mode="Markdown")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ آيدي غير صحيح")
        return
    if db.add_admin(uid):
        await update.message.reply_text(f"✅ تم رفع `{uid}` أدمن", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ `{uid}` أدمن بالفعل", parse_mode="Markdown")


@admin_only
async def del_admin_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("الاستخدام: `/deladmin <user_id>`", parse_mode="Markdown")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ آيدي غير صحيح")
        return
    if uid == ADMIN_ID:
        await update.message.reply_text("❌ لا يمكن حذف الأدمن الرئيسي")
        return
    if db.remove_admin(uid):
        await update.message.reply_text(f"✅ تم إزالة `{uid}` من الأدمنز", parse_mode="Markdown")
    else:
        await update.message.reply_text(f"⚠️ `{uid}` ليس أدمن", parse_mode="Markdown")


# ============================================================
# فك التشفير
# ============================================================
async def decrypt_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    user = message.from_user
    text = message.text or ""
    document = message.document

    # تسجيل المستخدم
    db.register_user(user.id, user.username or "", user.first_name or "")

    # حظر
    if db.is_banned(user.id):
        await message.reply_text("🚫 أنت محظور من استخدام البوت.")
        return

    # إيقاف
    if not db.get_bot_status() and not db.is_admin(user.id) and user.id != ADMIN_ID:
        await message.reply_text("⛔ البوت متوقف حاليًا.")
        return

    # تجاهل الأوامر
    if text.startswith("/"):
        return

    await message.reply_text("🔓 جاري فك التشفير... انتظر قليلاً")

    file_bytes = None
    if document:
        file = await document.get_file()
        file_bytes = bytes(await file.download_as_bytearray())
    elif text:
        file_bytes = text.encode('utf-8')

    if not file_bytes:
        await message.reply_text("❌ لم أستقبل أي ملف أو نص.")
        return

    # تجربة كل المفككات بالترتيب
    result = None
    config_type = "unknown"

    decryptors = [
        ("Dark Tunnel", DTDecryptor),
        ("HTTP Custom V1", HCDecryptorV1),
        ("HTTP Custom V2", HCDecryptorV2),
        ("HTTP Injector", EHIDecryptor),
        ("NPV Tunnel", NPVTDecryptor),
        ("SSC Custom", SSCDecryptor),
    ]

    for name, cls in decryptors:
        if result:
            break
        try:
            r = cls.execute(file_bytes)
            if r:
                result = r
                config_type = name
        except Exception:
            continue

    if result:
        db.increment_decrypt(config_type)
        header = f"💀 *DEVILS WILL RISE — {config_type}*\n{'=' * 40}\n\n"
        footer = f"\n\n{'=' * 40}\nOwner: @UnknownGuy9876 | Channel: {CHANNEL}"
        full = header + f"```json\n{result[:3500]}\n```" + footer
        # لو أطول من حد تليجرام
        if len(full) > 4000:
            full = header + f"```json\n{result[:3500]}\n... (تم قطع الباقي)\n```" + footer
        await message.reply_text(full, parse_mode="Markdown")
    else:
        await message.reply_text(
            "❌ فشل فك التشفير!\n\n"
            "تأكد من إرسال ملف إعدادات صالح أو رابط.\n"
            "المدعوم: Dark Tunnel, HTTP Custom, HTTP Injector, NPV Tunnel, SSC Custom"
        )


# ============================================================
# Main
# ============================================================
def main():
    print(f"💀 {BOT_NAME}")
    print(f"👑 Admin ID: {ADMIN_ID}")
    print("🚀 Starting bot...")

    # ضمان إن الأدمن الرئيسي مضاف
    if not db.is_admin(ADMIN_ID):
        db.add_admin(ADMIN_ID)

    app = Application.builder().token(BOT_TOKEN).build()

    # أوامر
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("admin", admin_panel))
    app.add_handler(CommandHandler("ban", ban_cmd))
    app.add_handler(CommandHandler("unban", unban_cmd))
    app.add_handler(CommandHandler("addadmin", add_admin_cmd))
    app.add_handler(CommandHandler("deladmin", del_admin_cmd))

    # أزرار لوحة التحكم
    app.add_handler(CallbackQueryHandler(callback_handler))

    # فك التشفير
    app.add_handler(MessageHandler(filters.TEXT | filters.Document.ALL, decrypt_handler))

    print("✅ Bot is running!")
    app.run_polling()


if __name__ == "__main__":
    main()
