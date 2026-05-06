import 'dotenv/config';
import { Telegraf, Markup } from 'telegraf';
import pg from 'pg';
import crypto from 'crypto';
const { Pool } = pg;

const bot = new Telegraf(process.env.BOT_TOKEN);

// PostgreSQL pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ADMIN IDS → array
const ADMIN_IDS = process.env.ADMIN_IDS.split(',').map(id => Number(id));

// Mini app URL
const APP_URL = (process.env.WEBAPP_URL || 'https://stars.uzgets.uz').replace(/\/$/, '');

// Majburiy obuna — yangiliklar kanali (https://t.me/uzgets)
const REQUIRED_CHANNEL = '@uzgets';

function parseTelegramChatId(envVal, fallback) {
  if (envVal === undefined || envVal === null || String(envVal).trim() === '') return fallback;
  const n = Number(String(envVal).trim());
  return Number.isFinite(n) ? n : fallback;
}

// Buyurtmalar kanali (.env ORDERS_CHANNEL)
const ORDERS_CHANNEL = parseTelegramChatId(process.env.ORDERS_CHANNEL, -1003986767336);

// Broadcast state - admin xabar yuborish uchun
const broadcastState = new Map();
// { adminId: { waiting: true, type: 'text' | 'photo' } }


// ===============================
// Kanalga obuna tekshirish
// ===============================
async function isSubscribed(ctx, userId) {
  try {
    const member = await ctx.telegram.getChatMember(REQUIRED_CHANNEL, userId);
    return ['member', 'administrator', 'creator'].includes(member.status);
  } catch (err) {
    // Agar bot kanalda admin bo'lmasa yoki xatolik bo'lsa
    console.error('❌ Obuna tekshirishda xato:', err?.message || err);
    return false;
  }
}

function getSubscribeText() {
  return `
📢 *Botdan foydalanish uchun kanalimizga obuna bo'ling!*

✅ Quyidagi tugma orqali kanalga obuna bo'ling
🔄 So'ng *"Tekshirish"* tugmasini bosing
`;
}

function getSubscribeKeyboard() {
  return Markup.inlineKeyboard([
    [Markup.button.url('📢 Kanalga obuna bo\'lish', 'https://t.me/uzgets')],
    [Markup.button.callback('✅ Tekshirish', 'check_subscription')]
  ]);
}


// ===============================
// CHIROYLI START XABARI
// ===============================
function getStartText(_name) {
  const offerUrl = `${APP_URL}/oferta`;
  return `
⭐ Uzgets ga xush kelibsiz!

Telegram Stars va Premium - barchasini bir joydan, tez va qulay sotib oling.

Boshlash uchun START tugmani bosing 👇

`;
}


// ===============================
// ADMIN START XABARI
// ===============================
function getAdminText(name) {
  return `
👑 *Admin panelga xush kelibsiz, ${name}!*

Quyida boshqaruv paneliga o‘tishingiz mumkin:
`;
}


// ===============================
// Xavfsiz reply funksiyasi
// ===============================
async function safeReply(ctx, text, keyboard) {
  try {
    await ctx.replyWithMarkdown(text, keyboard);
  } catch (err) {
    // 403 — user botni block qilgan
    if (err?.response?.error_code === 403) {
      console.log(`❌ User ${ctx.from?.id} botni block qilgan ➝ skip`);
      return;
    }

    console.error("❌ Reply error:", err);
  }
}


// ===============================
// /start komandasi
// ===============================
bot.start(async (ctx) => {
  const userId = ctx.from.id;
  const fullName = ctx.from.first_name;
  const username = ctx.from.username || `user_${userId}`; // Username bo'lmasa user_id ishlatiladi
  const language = ctx.from.language_code || 'uz';

  try {
    const userCheck = await pool.query('SELECT user_id FROM users WHERE user_id = $1', [String(userId)]);
    if (userCheck.rows.length === 0) {
      const new_code = crypto.randomBytes(6).toString("hex");
      await pool.query(
        `INSERT INTO users (name, username, user_id, referral_code, referrer_user_id, language)
         VALUES ($1, $2, $3, $4, null, $5)`,
        [fullName, username, String(userId), new_code, language]
      );
      console.log(`👤 Bot orqali yangi user ro'yxatdan o'tdi: ${userId} (${username || fullName})`);
    } else {
      // Mavjud foydalanuvchining ma'lumotlarini yangilab qo'yamiz (agar o'zgargan bo'lsa)
      await pool.query(
        `UPDATE users SET name = $1, username = $2 WHERE user_id = $3`,
        [fullName, username, String(userId)]
      );
    }
  } catch (err) {
    console.error("❌ Userni DB ga yozishda xato:", err);
  }

  // ADMIN — obuna talab qilinmaydi
  if (ADMIN_IDS.includes(userId)) {
    return await safeReply(
      ctx,
      getAdminText(fullName),
      Markup.inlineKeyboard([
        [
          Markup.button.webApp("Admin panel", `${APP_URL}/starsadmin`)
        ],
        [
          Markup.button.callback("Xabar yuborish", "broadcast_start")
        ]
      ])
    );
  }

  // Majburiy obuna tekshirish
  const subscribed = await isSubscribed(ctx, userId);
  if (!subscribed) {
    return await safeReply(ctx, getSubscribeText(), getSubscribeKeyboard());
  }

  // Obuna bo'lgan — davom etamiz
  await safeReply(
    ctx,
    getStartText(fullName),
    Markup.inlineKeyboard([
        [
          Markup.button.webApp("START", `${APP_URL}/`)
        ],
        
    ])
  );
});


// ===============================
// "Tekshirish" tugmasi callback
// ===============================
bot.action('check_subscription', async (ctx) => {
  const userId = ctx.from.id;
  const fullName = ctx.from.first_name;

  const subscribed = await isSubscribed(ctx, userId);

  if (!subscribed) {
    try {
      await ctx.answerCbQuery('❌ Siz hali kanalga obuna bo\'lmagansiz!', { show_alert: true });
    } catch (e) {}
    return;
  }

  // Obuna bo'lgan — database-ga yozish va referral bonusni berish
  try {
    // User'ni topish va subscribe_user = true qilish
    const userCheck = await pool.query(
      'SELECT user_id, username, referrer_user_id, subscribe_user FROM users WHERE user_id = $1',
      [String(userId)]
    );

    if (userCheck.rows.length > 0) {
      const user = userCheck.rows[0];
      
      // Agar hali subscribe bo'lmagan bo'lsa
      if (!user.subscribe_user) {
        // subscribe_user = true qilish
        await pool.query(
          'UPDATE users SET subscribe_user = true WHERE user_id = $1',
          [String(userId)]
        );
        console.log(`✅ User ${userId} subscribe_user = true qilindi`);

        // Agar bu user referral request'ga ega bo'lsa - subscribe_referrer ni true qilish
        try {
          await pool.query(
            "UPDATE referral_requests SET subscribe_referrer = true WHERE owner_user_id = $1 AND is_accepted = false AND rejected_at IS NULL",
            [String(userId)]
          );
          console.log(`✅ Referral request updated: ${userId} kanalga obuna bo'ldi`);
        } catch (err) {
          console.error("⚠️ Update referral request subscribe status error:", err.message);
        }

        // Agar referrer orqali kelgan bo'lsa - referralni tasdiqlash
        if (user.referrer_user_id) {
          try {
            const referrerResult = await pool.query(
              'SELECT username FROM users WHERE user_id = $1',
              [user.referrer_user_id]
            );

            if (referrerResult.rows.length > 0) {
              const referrerUsername = referrerResult.rows[0].username;
              const userName = user.username || String(userId);

              // Referrer ni total_referrals ni oshirish (Bonus +2 berilmaydi)
              await pool.query(
                `UPDATE users 
                 SET total_referrals = total_referrals + 1
                 WHERE user_id = $1`,
                [user.referrer_user_id]
              );

              console.log(`🎁 REFERRAL TASDIQLANDI: ${referrerUsername} ga yangi referral qo'shildi (${userName} kanalga obuna bo'ldi). Bonus berilmaydi.`);
            }
          } catch (bonusErr) {
            console.error('❌ Subscribe referral update error:', bonusErr.message);
          }
        }
      }
    }
  } catch (dbErr) {
    console.error('❌ Database update error:', dbErr.message);
  }

  // Eski xabarni o'chirish
  try {
    await ctx.deleteMessage();
  } catch (e) {}

  await safeReply(
    ctx,
    getStartText(fullName),
    Markup.inlineKeyboard([
        [
          Markup.button.webApp("START", `${APP_URL}/`)
        ],
        
    ])
  );

  try {
    await ctx.answerCbQuery('✅ Obuna tasdiqlandi!');
  } catch (e) {}
});


// ===============================
// 📢 BROADCAST TIZIMI
// ===============================

// Broadcast boshlash tugmasi
bot.action('broadcast_start', async (ctx) => {
  const userId = ctx.from.id;
  
  if (!ADMIN_IDS.includes(userId)) {
    return await ctx.answerCbQuery('❌ Ruxsat yo\'q', { show_alert: true });
  }

  await ctx.answerCbQuery();
  
  await ctx.reply(
    `📢 *Broadcast xabar yuborish*

Qanday turdagi xabar yubormoqchisiz?`,
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [
            { text: '📝 Faqat matn', callback_data: 'broadcast_text' },
            { text: '🖼 Rasm + matn', callback_data: 'broadcast_photo' }
          ],
          [
            { text: '❌ Bekor qilish', callback_data: 'broadcast_cancel' }
          ]
        ]
      }
    }
  );
});

// Faqat matn yuborish
bot.action('broadcast_text', async (ctx) => {
  const userId = ctx.from.id;
  
  if (!ADMIN_IDS.includes(userId)) return;

  await ctx.answerCbQuery();
  broadcastState.set(userId, { waiting: true, type: 'text' });
  
  await ctx.editMessageText(
    `📝 *Matn xabarni yuboring*

Barcha foydalanuvchilarga yuboriladigan matnni yozing:

_HTML formatda yozishingiz mumkin: <b>qalin</b>, <i>kursiv</i>, <a href="link">havola</a>_`,
    { parse_mode: 'Markdown' }
  );
});

// Rasm + matn yuborish
bot.action('broadcast_photo', async (ctx) => {
  const userId = ctx.from.id;
  
  if (!ADMIN_IDS.includes(userId)) return;

  await ctx.answerCbQuery();
  broadcastState.set(userId, { waiting: true, type: 'photo' });
  
  await ctx.editMessageText(
    `🖼 *Rasm va matn yuboring*

Rasm yuboring va caption (izoh) qo'shing.

_Caption HTML formatda bo'lishi mumkin_`,
    { parse_mode: 'Markdown' }
  );
});

// Bekor qilish
bot.action('broadcast_cancel', async (ctx) => {
  const userId = ctx.from.id;
  
  broadcastState.delete(userId);
  await ctx.answerCbQuery('❌ Bekor qilindi');
  await ctx.deleteMessage();
});

// Broadcast tasdiqlash
bot.action(/^broadcast_confirm_(.+)$/, async (ctx) => {
  const userId = ctx.from.id;
  
  if (!ADMIN_IDS.includes(userId)) return;

  const data = ctx.match[1];
  const state = broadcastState.get(userId);
  
  if (!state || !state.message) {
    return await ctx.answerCbQuery('❌ Xabar topilmadi', { show_alert: true });
  }

  const updateBroadcastMessage = async (text, extra = {}) => {
    const isMediaMessage = Boolean(
      ctx.callbackQuery?.message?.photo ||
      ctx.callbackQuery?.message?.video ||
      ctx.callbackQuery?.message?.document
    );

    try {
      if (isMediaMessage) {
        return await ctx.editMessageCaption(text, extra);
      }
      return await ctx.editMessageText(text, extra);
    } catch (editErr) {
      const description = editErr?.response?.description || editErr?.message || '';

      // If original message type doesn't match edit method, fallback safely.
      if (description.includes('there is no text in the message to edit')) {
        try {
          return await ctx.editMessageCaption(text, extra);
        } catch (_) {
          return await ctx.reply(text, extra);
        }
      }

      if (description.includes('there is no caption in the message to edit')) {
        try {
          return await ctx.editMessageText(text, extra);
        } catch (_) {
          return await ctx.reply(text, extra);
        }
      }

      if (description.includes('message is not modified')) {
        return;
      }

      return await ctx.reply(text, extra);
    }
  };

  await ctx.answerCbQuery('⏳ Yuborilmoqda...');
  await updateBroadcastMessage('⏳ *Broadcast boshlanmoqda...*', { parse_mode: 'Markdown' });

  // Barcha user_id larni olish
  try {
    const result = await pool.query("SELECT user_id FROM users WHERE user_id IS NOT NULL AND user_id != ''");
    const userIds = result.rows.map(r => String(r.user_id)).filter(id => id && id.length > 0);
    
    if (userIds.length === 0) {
      await updateBroadcastMessage('❌ Foydalanuvchilar topilmadi');
      broadcastState.delete(userId);
      return;
    }
    
    let sent = 0;
    let failed = 0;
    const total = userIds.length;

    console.log(`📢 Broadcast boshlanmoqda: ${total} ta userga | Admin: ${userId}`);

    // Batch yuborish (10 ta parallel)
    const BATCH_SIZE = 10;
    for (let i = 0; i < userIds.length; i += BATCH_SIZE) {
      const batch = userIds.slice(i, i + BATCH_SIZE);
      
      await Promise.all(batch.map(async (uid) => {
        try {
          if (state.type === 'photo' && state.photoId) {
            await bot.telegram.sendPhoto(uid, state.photoId, {
              caption: state.message,
              parse_mode: 'HTML'
            });
          } else {
            await bot.telegram.sendMessage(uid, state.message, {
              parse_mode: 'HTML',
              disable_web_page_preview: false
            });
          }
          sent++;
        } catch (err) {
          failed++;
          // 403 = blocked, 400 = chat not found — normal
          if (err?.response?.error_code !== 403 && err?.response?.error_code !== 400) {
            console.log(`Broadcast error to ${uid}:`, err.message);
          }
        }
      }));

      // Telegram limitlaridan qochish uchun kichik pauza
      if (i + BATCH_SIZE < userIds.length) {
        await new Promise(r => setTimeout(r, 100));
      }
    }

    broadcastState.delete(userId);

    await updateBroadcastMessage(
      `✅ *Broadcast yakunlandi!*

📊 *Statistika:*
├ Jami: ${total} ta user
├ ✅ Yuborildi: ${sent} ta
└ ❌ Xato: ${failed} ta`,
      { parse_mode: 'Markdown' }
    );

    console.log(`📢 BROADCAST: Admin ${userId} — ${sent}/${total} yuborildi`);

  } catch (err) {
    console.error('Broadcast error:', err);
    await updateBroadcastMessage('❌ Broadcast xatolik: ' + err.message);
    broadcastState.delete(userId);
  }
});

// Broadcast bekor qilish (tasdiqlash oynasida)
bot.action('broadcast_reject', async (ctx) => {
  const userId = ctx.from.id;
  
  broadcastState.delete(userId);
  await ctx.answerCbQuery('❌ Bekor qilindi');
  await ctx.deleteMessage();
});

// Admin xabar yozganda (matn)
bot.on('text', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const state = broadcastState.get(userId);
    
    if (!state || !state.waiting || !ADMIN_IDS.includes(userId)) return;
    
    if (state.type === 'text') {
      const messageText = ctx.message.text;
      
      // Xabarni saqlash
      state.message = messageText;
      state.waiting = false;
      broadcastState.set(userId, state);

      // Tasdiqlash so'rash (parse_mode yo'q - user xabarida maxsus belgilar bo'lishi mumkin)
      await ctx.reply(
        `📋 Xabar tayyor:

${messageText}

━━━━━━━━━━━━━━
Barcha foydalanuvchilarga yuborilsinmi?`,
        {
          reply_markup: {
            inline_keyboard: [
              [
                { text: '✅ Yuborish', callback_data: 'broadcast_confirm_text' },
                { text: '❌ Bekor', callback_data: 'broadcast_reject' }
              ]
            ]
          }
      }
    );
    }
  } catch (err) {
    console.error('❌ Broadcast text handler error:', err);
  }
});

// Admin rasm yuborganda
bot.on('photo', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const state = broadcastState.get(userId);
    
    if (!state || !state.waiting || state.type !== 'photo' || !ADMIN_IDS.includes(userId)) return;
    
    const photo = ctx.message.photo;
    const photoId = photo[photo.length - 1].file_id; // Eng yuqori sifatli
  const caption = ctx.message.caption || '';
  
  // Xabarni saqlash
  state.photoId = photoId;
  state.message = caption;
  state.waiting = false;
  broadcastState.set(userId, state);

  // Tasdiqlash so'rash (parse_mode yo'q - user caption'ida maxsus belgilar bo'lishi mumkin)
  await ctx.replyWithPhoto(photoId, {
    caption: `📋 Rasm tayyor!

${caption ? `Caption: ${caption}` : '(Caption yo\'q)'}

━━━━━━━━━━━━━━
Barcha foydalanuvchilarga yuborilsinmi?`,
    reply_markup: {
      inline_keyboard: [
        [
          { text: '✅ Yuborish', callback_data: 'broadcast_confirm_photo' },
          { text: '❌ Bekor', callback_data: 'broadcast_reject' }
        ]
      ]
    }
  });
  } catch (err) {
    console.error('❌ Broadcast photo handler error:', err);
  }
});


// ===============================
// Botni ishga tushirish
// ===============================
bot.launch()
  .then(() => console.log("🚀 Bot ishlayapti..."))
  .catch(err => console.error("Bot launch error:", err));
