import express from "express";
import pkg from "pg";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Telegraf } from 'telegraf';
dotenv.config();
const { Pool } = pkg;
const app = express();
const PORT = Number(process.env.PORT) || 1001;
const INTERNAL_API_BASE = (process.env.INTERNAL_API_BASE || `http://127.0.0.1:${PORT}`).replace(/\/$/, '');
const BALANCE_CHECKER_PORT = Number(process.env.BALANCE_CHECKER_PORT) || 1002;
const BALANCE_CHECKER_URL = (process.env.BALANCE_CHECKER_URL || `http://127.0.0.1:${BALANCE_CHECKER_PORT}`).replace(/\/$/, '');
// ======================
// 🛡️ Trust Proxy — Nginx reverse proxy uchun
// ======================
app.set('trust proxy', 1);
// ======================
// 🛡️ SECURITY: Helmet — HTTP security headers
// ======================
app.use(helmet({
  contentSecurityPolicy: false, // API server uchun kerak emas
  crossOriginEmbedderPolicy: false,
}));
// ======================
// 🛡️ SECURITY: CORS — faqat ruxsat etilgan domenlar
// ======================
const ALLOWED_ORIGINS = [
  'https://starsx.starstg.uz',
  'https://www.starsx.starstg.uz',
  'https://web.telegram.org',
  'https://t.me',
  process.env.WEBAPP_URL,
].filter(Boolean);
// Development uchun localhost ham qo'shiladi
if (process.env.NODE_ENV !== 'production') {
  ALLOWED_ORIGINS.push('http://localhost:1000');
}
app.use(cors({
  origin: function (origin, callback) {
    // Server-to-server (bot.js, balanceChecker) origin=undefined bo'ladi
    if (!origin) return callback(null, true);
    
    if (ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      console.warn(`🚫 CORS bloklandi: ${origin}`);
      callback(new Error('CORS policy: Origin not allowed'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Telegram-Init-Data', 'X-Internal-Key'],
}));
app.use(express.json({ limit: '1mb' }));

// ======================
// ⏱️ REQUEST TIMEOUT — So'rovlar 30 sekundda timeout bo'ladi
// ======================
app.use((req, res, next) => {
  req.setTimeout(30000, () => {
    console.warn(`⏱️ Request timeout: ${req.method} ${req.url}`);
    if (!res.headersSent) {
      res.status(408).json({ error: 'Request timeout' });
    }
  });
  next();
});

// ======================
// 🛡️ SECURITY: Rate Limiting
// ======================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 daqiqa
  max: 200, // har bir IP dan 200 ta request
  message: { error: 'Juda ko\'p so\'rov. 18 daqiqadan keyin urinib ko\'ring.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const orderLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 daqiqa
  max: 20, // har bir IP dan 20 ta order
  message: { error: 'Juda ko\'p order. 8 daqiqadan keyin urinib ko\'ring.' },
});
const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 daqiqa
  max: 15, // har bir IP dan 15 ta search
  message: { error: 'Juda ko\'p qidiruv. 1 daqiqadan keyin urinib ko\'ring.' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Juda ko\'p urinish.' },
});

// Admin uchun yumshoq rate limit
const adminLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 daqiqa
  max: 100, // 100 ta request
  message: { error: 'Juda ko\'p so\'rov. 1 daqiqadan keyin urinib ko\'ring.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Admin routes uchun alohida rate limit
app.use('/api/admin/', adminLimiter);

// Barcha API larga umumiy rate limit
app.use('/api/', generalLimiter);

// ======================
// 🛡️ SECURITY: Telegram WebApp initData validatsiya
// ======================
function validateTelegramInitData(initData) {
  if (!initData) return null;
  
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    
    // hash ni olib tashlaymiz va sortlaymiz
    params.delete('hash');
    const dataCheckArr = [];
    params.sort();
    params.forEach((val, key) => dataCheckArr.push(`${key}=${val}`));
    const dataCheckString = dataCheckArr.join('\n');
    
    // HMAC SHA256 bilan tekshirish
    const botToken = process.env.BOT_TOKEN;
    if (!botToken) return null;
    
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(botToken)
      .digest();
    
    const checkHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');
    
    if (checkHash !== hash) {
      console.warn('🚫 Telegram initData hash mos kelmadi!');
      return null;
    }
    
    // auth_date ni tekshirish (8 daqiqadan eski bo'lmasligi kerak)
    const authDate = parseInt(params.get('auth_date'));
    const now = Math.floor(Date.now() / 1000);
    if (now - authDate > 86400) { // 24 soat
      console.warn('🚫 Telegram initData muddati o\'tgan!');
      return null;
    }
    
    // User ma'lumotlarini qaytarish
    const userStr = params.get('user');
    if (!userStr) return null;
    
    return JSON.parse(userStr);
  } catch (err) {
    console.error('❌ initData validatsiya xatosi:', err.message);
    return null;
  }
}
// Telegram auth middleware — foydalanuvchi endpointlari uchun
function telegramAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  
  // Development mode da skip qilish mumkin
  if (process.env.NODE_ENV !== 'production' && !initData) {
    return next();
  }
  
  const user = validateTelegramInitData(initData);
  if (!user) {
    return res.status(401).json({ error: 'Telegram autentifikatsiya muvaffaqiyatsiz' });
  }
  
  req.telegramUser = user;
  next();
}
// ======================
// 🛡️ SECURITY: Admin auth middleware
// ======================
function adminAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  
  // Development mode da initData bo'lmasa ham o'tkazish
  if (process.env.NODE_ENV !== 'production' && !initData) {
    req.adminUser = { id: 0, username: 'dev_admin' };
    return next();
  }
  
  if (!initData) {
    return res.status(401).json({ error: 'Autentifikatsiya kerak' });
  }
  
  const user = validateTelegramInitData(initData);
  if (!user) {
    return res.status(401).json({ error: 'Telegram autentifikatsiya muvaffaqiyatsiz' });
  }
  
  const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(id => Number(id.trim()));
  
  if (!ADMIN_IDS.includes(user.id)) {
    console.warn(`🚫 Admin ruxsatsiz kirish urinishi: ${user.id} (${user.username || 'noma\'lum'})`);
    return res.status(403).json({ error: 'Sizda admin huquqi yo\'q' });
  }
  
  req.adminUser = user;
  next();
}
// ======================
// 🛡️ SECURITY: Internal API middleware (bot.js va balanceChecker uchun)
// ======================
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.INTERNAL_API_SECRET) {
  console.warn('⚠️ INTERNAL_API_SECRET .env da yo\'q! Tasodifiy kalit ishlatilmoqda.');
  console.log(`🔑 INTERNAL_API_SECRET=${INTERNAL_SECRET}`);
  console.log('☝️ Bu kalitni .env faylga qo\'shing va bot.js / balanceChecker.js ga ham o\'rnating!');
}
function internalAuth(req, res, next) {
  const key = req.headers['x-internal-key'];
  
  // Localhost dan kelgan so'rovlar tekshiriladi
  const ip = req.ip || req.connection?.remoteAddress || '';
  const isLocalhost = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  
  // Tashqi IP — bloklash
  if (!isLocalhost) {
    console.warn(`🚫 Tashqi IP dan internal API ga kirish urinishi: ${ip}`);
    return res.status(403).json({ error: 'Ruxsat berilmagan' });
  }
  
  // Localhost — lekin kalit majburiy
  if (key !== INTERNAL_SECRET) {
    console.warn(`🚫 Internal API kalit noto'g'ri! IP: ${ip}`);
    return res.status(403).json({ error: 'Noto\'g\'ri kalit' });
  }
  
  next();
}
const PREMIUM_3 = parseInt(process.env.VITE_PREMIUM_3);
const PREMIUM_6 = parseInt(process.env.VITE_PREMIUM_6);
const PREMIUM_12 = parseInt(process.env.VITE_PREMIUM_12);
// 🛡️ Stars narxi — backend da ham tekshiriladi (frontendga ishonish MUMKIN EMAS!)
const STARS_PRICE_PER_UNIT = parseInt(process.env.STARS_PRICE_PER_UNIT) || parseInt(process.env.VITE_NARX);
if (!STARS_PRICE_PER_UNIT || STARS_PRICE_PER_UNIT <= 0) {
  console.error('❌ STARS_PRICE_PER_UNIT yoki VITE_NARX .env da topilmadi!');
  console.error('💡 .env faylga qo\'shing: STARS_PRICE_PER_UNIT=220');
  process.exit(1);
}
console.log(`💰 Stars narxi: 1⭐ = ${STARS_PRICE_PER_UNIT} UZS`);

// ======================
// 🛡️ GLOBAL PRICE CACHE - Barcha pending orderlar narxlari
// ======================
// In-memory cache - database query'larni kamaytirish uchun
// { price: { orderId, createdAt, orderType } }
const globalUsedPrices = new Map();

// ======================
// 📊 LEADERBOARD CACHE - Og'ir querylarni keshlash (30 sekund)
// ======================
const leaderboardCache = {
  data: null,
  timestamp: 0,
  TTL: 30 * 1000, // 30 sekund
};

const referralLeaderboardCache = {
  data: null,
  timestamp: 0,
  TTL: 30 * 1000,
};

/** Savdo TOP ro‘yxatida ko‘rsatilmasligi kerak bo‘lgan owner_user_id lar */
const LEADERBOARD_EXCLUDED_OWNER_IDS = new Set(["6568473441"]);

function filterSalesLeaderboardTop10(rows) {
  if (!rows?.length) return [];
  return rows
    .filter((r) => !LEADERBOARD_EXCLUDED_OWNER_IDS.has(String(r.owner_user_id)))
    .slice(0, 10);
}

function getCachedLeaderboard() {
  if (leaderboardCache.data && Date.now() - leaderboardCache.timestamp < leaderboardCache.TTL) {
    return leaderboardCache.data;
  }
  return null;
}

function setCachedLeaderboard(data) {
  leaderboardCache.data = data;
  leaderboardCache.timestamp = Date.now();
}

function getCachedReferralLeaderboard() {
  if (referralLeaderboardCache.data && Date.now() - referralLeaderboardCache.timestamp < referralLeaderboardCache.TTL) {
    return referralLeaderboardCache.data;
  }
  return null;
}

function setCachedReferralLeaderboard(data) {
  referralLeaderboardCache.data = data;
  referralLeaderboardCache.timestamp = Date.now();
}

// Server ishga tushganda pending orderlarni yuklash
async function loadPendingOrdersToCache() {
  try {
    // Avval eski pending orderlarni expired qilish (8 daqiqadan eski)
    const expireResult = await pool.query(`
      UPDATE orders 
      SET status = 'expired', payment_status = 'expired'
      WHERE status = 'pending' 
        AND payment_status = 'pending'
        AND created_at < (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'
      RETURNING id, owner_user_id, order_type
    `);
    
    if (expireResult.rows.length > 0) {
      console.log(`🧹 ${expireResult.rows.length} ta eski pending order expired qilindi`);
      
      // Expired bo'lgan orderlar uchun cache tozalash va xabar yuborish
      for (const row of expireResult.rows) {
        // Barcha slot turlarini bo'shatish
        releasePriceSlotByOrderId(row.id);
        releaseDiscountPriceSlotByOrderId(row.id);
        releasePremiumPriceSlotByOrderId(row.id);
        releaseGiftPriceSlotByOrderId(row.id);
        
        // Xabar yuborish (faqat 1 marta)
        if (['stars', 'gift', 'premium'].includes(row.order_type) && row.owner_user_id && bot) {
          try {
            let expiredNotificationText = '';
            if (row.order_type === 'stars') {
              expiredNotificationText = `⚠️ Siz stars sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            } else if (row.order_type === 'gift') {
              expiredNotificationText = `⚠️ Siz gift yuborishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            } else if (row.order_type === 'premium') {
              expiredNotificationText = `⚠️ Siz premium sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            }
            
            await bot.telegram.sendMessage(row.owner_user_id, expiredNotificationText);
            
            // expired_notified ni true qilish
            await pool.query(
              `UPDATE orders SET expired_notified = true WHERE id = $1`,
              [row.id]
            );
            console.log(`📩 Expired order xabari yuborildi (startup): user=${row.owner_user_id}, order=#${row.id}, type=${row.order_type}`);
          } catch (notifyErr) {
            console.error(`❌ Expired order xabari yuborishda xato (user=${row.owner_user_id}):`, notifyErr.message);
          }
        }
      }
    }
    
    // Faqat oxirgi 5 daqiqadagi pending orderlarni yuklash
    const result = await pool.query(
      "SELECT id, summ, order_type, type_amount, created_at FROM orders WHERE status = 'pending' AND payment_status = 'pending' AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'"
    );
    
    globalUsedPrices.clear();
    
    // Slot tizimlarini tozalash
    for (const key in priceSlots) delete priceSlots[key];
    
    for (const order of result.rows) {
      // Global cache ga qo'shish
      globalUsedPrices.set(order.summ, {
        orderId: order.id,
        orderType: order.order_type,
        createdAt: new Date(order.created_at).getTime()
      });
      
      // Slot tizimiga yuklash (faqat stars uchun)
      if (order.order_type === 'stars' && order.type_amount) {
        const starsAmount = order.type_amount;
        const maxPrice = starsAmount * STARS_PRICE_PER_UNIT;
        const diff = maxPrice - order.summ;
        
        // Slot index'ni aniqlash (yangi formula: diff = slotIndex * 50)
        let slotIndex = -1;
        if (diff >= 0 && diff <= 950 && diff % 50 === 0) {
          slotIndex = diff / 50;
        }
        
        if (slotIndex >= 0 && slotIndex < 20) {
          if (!priceSlots[starsAmount]) priceSlots[starsAmount] = {};
          priceSlots[starsAmount][slotIndex] = {
            orderId: order.id,
            createdAt: new Date(order.created_at).getTime()
          };
          console.log(`📦 Stars slot yuklandi: ${starsAmount} stars, slot ${slotIndex}, order #${order.id}, price=${order.summ}`);
        }
      }
    }
    
    console.log(`📦 Cache yuklandi: ${globalUsedPrices.size} ta pending order (oxirgi 5 daqiqa)`);
  } catch (err) {
    console.error('❌ Pending orderlarni yuklashda xato:', err.message);
  }
}

// Cache ga narx qo'shish
function addPriceToCache(price, orderId, orderType) {
  globalUsedPrices.set(price, {
    orderId,
    orderType,
    createdAt: Date.now()
  });
}

// Cache dan narx o'chirish
function removePriceFromCache(price) {
  globalUsedPrices.delete(price);
}

// Order ID bo'yicha cache dan o'chirish
function removePriceFromCacheByOrderId(orderId) {
  for (const [price, data] of globalUsedPrices.entries()) {
    if (data.orderId === orderId) {
      globalUsedPrices.delete(price);
      return price;
    }
  }
  return null;
}

// Narx band yoki yo'qligini tekshirish (O(1) tezlik)
function isPriceUsed(price) {
  return globalUsedPrices.has(price);
}

// ======================
// ⏰ EXPIRED ORDERS PROCESSING - Har 1 daqiqada
// ======================
setInterval(async () => {
  try {
    // 8 daqiqadan eski pending orderlarni expired qilish
    const expireResult = await pool.query(`
      UPDATE orders 
      SET status = 'expired', payment_status = 'expired'
      WHERE status = 'pending' 
        AND payment_status = 'pending'
        AND created_at < (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'
      RETURNING id, summ, applied_promocode, owner_user_id, order_type
    `);
    
    if (expireResult.rows.length > 0) {
      console.log(`🧹 ${expireResult.rows.length} ta eski pending order expired qilindi`);
      // Cache dan ham o'chirish (stars va discount slotlar)
      for (const row of expireResult.rows) {
        globalUsedPrices.delete(row.summ);
        releasePriceSlotByOrderId(row.id);
        releaseDiscountPriceSlotByOrderId(row.id);
        releasePremiumPriceSlotByOrderId(row.id);
        releaseGiftPriceSlotByOrderId(row.id);

        if (row.applied_promocode) {
          await pool.query(
            `UPDATE promocodes SET used_count = GREATEST(used_count - 1, 0) WHERE code = $1`,
            [row.applied_promocode]
          );
        }

        // Order expired bo'lsa, foydalanuvchiga xabar yuborish (faqat 1 marta)
        if (['stars', 'gift', 'premium'].includes(row.order_type) && row.owner_user_id && bot) {
          try {
            let expiredNotificationText = '';
            if (row.order_type === 'stars') {
              expiredNotificationText = `⚠️ Siz stars sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            } else if (row.order_type === 'gift') {
              expiredNotificationText = `⚠️ Siz gift yuborishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            } else if (row.order_type === 'premium') {
              expiredNotificationText = `⚠️ Siz premium sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
            }
            
            await bot.telegram.sendMessage(row.owner_user_id, expiredNotificationText);
            
            // expired_notified ni true qilish
            await pool.query(
              `UPDATE orders SET expired_notified = true WHERE id = $1`,
              [row.id]
            );
            console.log(`📩 Expired order xabari yuborildi: user=${row.owner_user_id}, order=#${row.id}, type=${row.order_type}`);
          } catch (notifyErr) {
            console.error(`❌ Expired order xabari yuborishda xato (user=${row.owner_user_id}):`, notifyErr.message);
          }
        }
      }
    }
  } catch (err) {
    console.error('❌ Expired orders processing xatosi:', err.message);
  }
}, 60 * 1000); // Har 1 daqiqa

// ======================
// 🧹 DEEP CACHE SYNC - Har 1 soatda (slot sinxronizatsiya)
// ======================
setInterval(async () => {
  try {
    // Bazadan haqiqiy pending orderlarni olish (faqat oxirgi 5 daqiqadagi)
    const result = await pool.query(
      "SELECT summ FROM orders WHERE status = 'pending' AND payment_status = 'pending' AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'"
    );
    
    const dbPrices = new Set(result.rows.map(r => r.summ));
    
    // Cache da bor lekin bazada yo'q narxlarni o'chirish
    for (const [price] of globalUsedPrices.entries()) {
      if (!dbPrices.has(price)) {
        globalUsedPrices.delete(price);
      }
    }

    // ===== SLOT CACHE SINXRONIZATSIYASI =====
    // Bazadan barcha pending orderlarni olish (slotlarni sinxronlash uchun)
    const pendingOrders = await pool.query(
      "SELECT id, order_type, type_amount FROM orders WHERE status = 'pending' AND payment_status = 'pending' AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'"
    );
    
    const pendingOrderIds = new Set(pendingOrders.rows.map(r => r.id));
    
    // 1. priceSlots (Stars) - bazada yo'q orderlarni tozalash
    for (const starsAmount in priceSlots) {
      const slots = priceSlots[starsAmount];
      for (const slotIndex in slots) {
        if (!pendingOrderIds.has(slots[slotIndex].orderId)) {
          console.log(`🧹 Stars ${starsAmount} - Slot ${slotIndex} sinxronlandi (bazada yo'q): orderId=${slots[slotIndex].orderId}`);
          delete slots[slotIndex];
        }
      }
      // Bo'sh poollarni o'chirish
      if (Object.keys(slots).length === 0) {
        delete priceSlots[starsAmount];
      }
    }
    
    // 2. discountPriceSlots - bazada yo'q orderlarni tozalash
    for (const packageId in discountPriceSlots) {
      const slots = discountPriceSlots[packageId];
      for (const slotIndex in slots) {
        if (!pendingOrderIds.has(slots[slotIndex].orderId)) {
          console.log(`🧹 Discount ${packageId} - Slot ${slotIndex} sinxronlandi (bazada yo'q): orderId=${slots[slotIndex].orderId}`);
          delete slots[slotIndex];
        }
      }
      if (Object.keys(slots).length === 0) {
        delete discountPriceSlots[packageId];
      }
    }
    
    // 3. premiumPriceSlots - bazada yo'q orderlarni tozalash
    for (const months in premiumPriceSlots) {
      const slots = premiumPriceSlots[months];
      for (const slotIndex in slots) {
        if (!pendingOrderIds.has(slots[slotIndex].orderId)) {
          console.log(`🧹 Premium ${months}m - Slot ${slotIndex} sinxronlandi (bazada yo'q): orderId=${slots[slotIndex].orderId}`);
          delete slots[slotIndex];
        }
      }
      if (Object.keys(slots).length === 0) {
        delete premiumPriceSlots[months];
      }
    }
    
    // 4. giftPriceSlots - bazada yo'q orderlarni tozalash
    for (const giftStars in giftPriceSlots) {
      const slots = giftPriceSlots[giftStars];
      for (const slotIndex in slots) {
        if (!pendingOrderIds.has(slots[slotIndex].orderId)) {
          console.log(`🧹 Gift ${giftStars}⭐ - Slot ${slotIndex} sinxronlandi (bazada yo'q): orderId=${slots[slotIndex].orderId}`);
          delete slots[slotIndex];
        }
      }
      if (Object.keys(slots).length === 0) {
        delete giftPriceSlots[giftStars];
      }
    }

    // Cache holati haqida log
    const totalStarsSlots = Object.values(priceSlots).reduce((sum, slots) => sum + Object.keys(slots).length, 0);
    const totalDiscountSlots = Object.values(discountPriceSlots).reduce((sum, slots) => sum + Object.keys(slots).length, 0);
    const totalPremiumSlots = Object.values(premiumPriceSlots).reduce((sum, slots) => sum + Object.keys(slots).length, 0);
    const totalGiftSlots = Object.values(giftPriceSlots).reduce((sum, slots) => sum + Object.keys(slots).length, 0);
    
    if (totalStarsSlots > 0 || totalDiscountSlots > 0 || totalPremiumSlots > 0 || totalGiftSlots > 0) {
      console.log(`📊 Cache holati: Stars=${totalStarsSlots}, Discount=${totalDiscountSlots}, Premium=${totalPremiumSlots}, Gift=${totalGiftSlots} slot(lar)`);
    }
  } catch (err) {
    console.error('❌ Cache tozalashda xato:', err.message);
  }
}, 60 * 60 * 1000); // Har 1 soat

// ======================
// 🎯 PRICE SLOT SYSTEM - Dinamik narx tizimi (Stars * NARX so'm)
// ======================
// Har bir Stars miqdori uchun alohida slot pool:
// MaxPrice = starsAmount * NARX (240 so'm)
// 20 ta slot: -50 so'm step har bir slot uchun
// ┌─────────────────────────────────────────────────────────────────┐
// │ Misol: 50 Stars (maxPrice = 12,000 so'm)                        │
// ├─────────────────────────────────────────────────────────────────┤
// │ 20 ta slot (-50 so'm step):                                     │
// │ Slot 0: 12,000 | Slot 1: 11,950 | Slot 2: 11,900 | ...          │
// │ ... | Slot 19: 11,050                                           │
// │ Oraliq: 12,000 - 11,050 = 950 so'm                             │
// └─────────────────────────────────────────────────────────────────┘
const PRICE_SLOT_CONFIG = {
  MAX_SLOTS: 20,           // Maksimum parallel orderlar (0-19)
  SLOT_TIMEOUT: 5 * 60 * 1000, // 5 daqiqa (ms)
};

// ======================
// 🔒 SIMPLE ASYNC LOCK — Race condition oldini olish
// ======================
const slotLocks = new Map(); // { key: Promise }

async function withSlotLock(key, fn) {
  // Oldingi lock tugashini kutish
  while (slotLocks.has(key)) {
    await slotLocks.get(key);
  }
  
  // Yangi lock yaratish
  let releaseLock;
  const lockPromise = new Promise(resolve => {
    releaseLock = resolve;
  });
  slotLocks.set(key, lockPromise);
  
  try {
    return await fn();
  } finally {
    slotLocks.delete(key);
    releaseLock();
  }
}

// In-memory price slot tracker
// Har bir stars miqdori uchun alohida slot pool
// Key: starsAmount (50, 100, 200...) - har bir miqdor uchun alohida pool
const priceSlots = {};

// Get available price slot for Stars (har bir stars miqdori uchun alohida pool)
function getAvailablePriceSlot(starsAmount) {
  const key = String(starsAmount); // Har bir miqdor uchun alohida pool
  const now = Date.now();
  
  // Initialize if not exists
  if (!priceSlots[key]) {
    priceSlots[key] = {};
  }
  
  const slots = priceSlots[key];
  
  // Clean up expired slots
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (slots[i]) {
      const elapsed = now - slots[i].createdAt;
      if (elapsed > PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
        console.log(`🧹 Stars ${starsAmount} - Slot ${i} tozalandi (expired)`);
        delete slots[i];
      }
    }
  }
  
  // Find first available slot (0-indexed)
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (!slots[i]) {
      return i;
    }
  }
  
  // All slots are taken
  return -1;
}

// Reserve a price slot (har bir stars miqdori uchun alohida pool)
function reservePriceSlot(starsAmount, slotIndex, orderId) {
  const key = String(starsAmount);
  
  if (!priceSlots[key]) {
    priceSlots[key] = {};
  }
  
  priceSlots[key][slotIndex] = {
    orderId: orderId,
    createdAt: Date.now()
  };
  
  const price = calculateSlotPrice(starsAmount, slotIndex);
  console.log(`🎯 Stars ${starsAmount} - Slot ${slotIndex} rezerv qilindi: orderId=${orderId}, price=${price} so'm`);
}

// Release a price slot by orderId (barcha poollardan qidirish)
function releasePriceSlotByOrderId(orderId, starsAmount = null) {
  // Agar starsAmount berilgan bo'lsa, faqat shu pooldan qidirish
  if (starsAmount) {
    const key = String(starsAmount);
    const slots = priceSlots[key];
    if (slots) {
      for (const slotIndex in slots) {
        if (slots[slotIndex].orderId === orderId) {
          console.log(`🔓 Stars ${starsAmount} - Slot ${slotIndex} bo'shatildi: orderId=${orderId}`);
          delete slots[slotIndex];
          return true;
        }
      }
    }
    return false;
  }
  
  // Agar starsAmount berilmagan bo'lsa, barcha poollardan qidirish
  for (const key in priceSlots) {
    const slots = priceSlots[key];
    for (const slotIndex in slots) {
      if (slots[slotIndex].orderId === orderId) {
        console.log(`🔓 Stars ${key} - Slot ${slotIndex} bo'shatildi: orderId=${orderId}`);
        delete slots[slotIndex];
        return true;
      }
    }
  }
  return false;
}

// Calculate price for a slot - YANGI CHIROYLI NARX TIZIMI
// Har bir stars miqdori uchun 20 ta slot:
// - maxPrice = stars * 240 (masalan: 50 stars = 12000, 100 stars = 24000)
// - minPrice = maxPrice - 1000 (masalan: 50 stars = 11000, 100 stars = 23000)
// - Step: -50 so'm har bir slot uchun
// 
// Misol (50 stars, maxPrice=12000):
// Slot 0: 12000, Slot 1: 11950, Slot 2: 11900, ... Slot 19: 11050
// Slot 20 yo'q - faqat 20 ta slot (0-19)
function calculateSlotPrice(starsAmount, slotIndex) {
  const maxPrice = starsAmount * STARS_PRICE_PER_UNIT; // Asosiy/max narx: stars * 240
  // Har bir slot -50 so'm kamayadi
  return maxPrice - (slotIndex * 50);
}

// Narxdan slot indexni aniqlash (teskari formula)
function getSlotIndexFromPrice(starsAmount, price) {
  const maxPrice = starsAmount * STARS_PRICE_PER_UNIT;
  const diff = maxPrice - price;
  if (diff < 0 || diff > 950 || diff % 50 !== 0) return -1;
  return diff / 50;
}

// Get current slot info for debugging (har bir stars miqdori uchun)
function getPriceSlotsInfo(starsAmount = null) {
  if (starsAmount) {
    const key = String(starsAmount);
    if (!priceSlots[key]) {
      return { starsAmount, totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS, usedSlots: 0, slots: {} };
    }
    const slots = priceSlots[key];
    const usedSlots = Object.keys(slots).length;
    return {
      starsAmount,
      totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
      usedSlots: usedSlots,
      availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - usedSlots,
      slots: slots
    };
  }
  
  // Barcha poollarni ko'rsatish
  const allPools = {};
  for (const key in priceSlots) {
    const slots = priceSlots[key];
    allPools[key] = {
      totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
      usedSlots: Object.keys(slots).length,
      availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - Object.keys(slots).length
    };
  }
  return allPools;
}

// ======================
// 🎯 DISCOUNT PRICE SLOT SYSTEM - Chegirma paketlari uchun chiroyli narx tizimi
// ======================
// Har bir chegirma paketi uchun alohida slot pool
// BasePrice = chegirma paketi narxi (discounted_price)
// 20 ta slot: -50 so'm step har bir slot uchun
// ┌─────────────────────────────────────────────────────────────────┐
// │ Misol: Chegirma paketi 1000 Stars = 200,000 so'm                │
// ├─────────────────────────────────────────────────────────────────┤
// │ 20 ta slot (-50 so'm step):                                     │
// │ Slot 0: 200,000 | Slot 1: 199,950 | Slot 2: 199,900 | ...       │
// │ ... | Slot 19: 199,050                                          │
// │ Oraliq: 200,000 - 199,050 = 950 so'm                           │
// └─────────────────────────────────────────────────────────────────┘

// In-memory discount price slot tracker: { packageId: { slotIndex: { orderId, createdAt } } }
const discountPriceSlots = {};

// Get available discount price slot (har bir chegirma paketi uchun alohida pool)
function getAvailableDiscountPriceSlot(packageId) {
  const key = String(packageId);
  const now = Date.now();
  
  // Initialize if not exists
  if (!discountPriceSlots[key]) {
    discountPriceSlots[key] = {};
  }
  
  const slots = discountPriceSlots[key];
  
  // Clean up expired slots
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (slots[i]) {
      const elapsed = now - slots[i].createdAt;
      if (elapsed > PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
        console.log(`🧹 Discount Package ${packageId} - Slot ${i} tozalandi (expired)`);
        delete slots[i];
      }
    }
  }
  
  // Find first available slot (0-indexed)
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (!slots[i]) {
      return i;
    }
  }
  
  // All slots are taken
  return -1;
}

// Reserve a discount price slot
function reserveDiscountPriceSlot(packageId, slotIndex, orderId, basePrice) {
  const key = String(packageId);
  
  if (!discountPriceSlots[key]) {
    discountPriceSlots[key] = {};
  }
  
  discountPriceSlots[key][slotIndex] = {
    orderId: orderId,
    createdAt: Date.now()
  };
  
  const price = calculateDiscountSlotPrice(basePrice, slotIndex);
  console.log(`🎯 Discount Package ${packageId} - Slot ${slotIndex} rezerv qilindi: orderId=${orderId}, price=${price} so'm`);
}

// Release a discount price slot by orderId
function releaseDiscountPriceSlotByOrderId(orderId, packageId = null) {
  // Agar packageId berilgan bo'lsa, faqat shu pooldan qidirish
  if (packageId) {
    const key = String(packageId);
    const slots = discountPriceSlots[key];
    if (slots) {
      for (const slotIndex in slots) {
        if (slots[slotIndex].orderId === orderId) {
          console.log(`🔓 Discount Package ${packageId} - Slot ${slotIndex} bo'shatildi: orderId=${orderId}`);
          delete slots[slotIndex];
          return true;
        }
      }
    }
    return false;
  }
  
  // Agar packageId berilmagan bo'lsa, barcha poollardan qidirish
  for (const key in discountPriceSlots) {
    const slots = discountPriceSlots[key];
    for (const slotIndex in slots) {
      if (slots[slotIndex].orderId === orderId) {
        console.log(`🔓 Discount Package ${key} - Slot ${slotIndex} bo'shatildi: orderId=${orderId}`);
        delete slots[slotIndex];
        return true;
      }
    }
  }
  return false;
}

// Calculate discount slot price - YANGI CHIROYLI NARX TIZIMI (Stars bilan bir xil)
// Asosiy narx: chegirma paketi narxi (discounted_price)
// 20 ta slot: -50 so'm step har bir slot uchun
// Misol (basePrice = 200000):
// Slot 0: 200000, Slot 1: 199950, Slot 2: 199900, ... Slot 19: 199050
function calculateDiscountSlotPrice(basePrice, slotIndex) {
  // Har bir slot -50 so'm kamayadi (Stars bilan bir xil)
  return basePrice - (slotIndex * 50);
}

// Narxdan slot indexni aniqlash (teskari formula)
function getDiscountSlotIndexFromPrice(basePrice, price) {
  const diff = basePrice - price;
  if (diff < 0 || diff > 950 || diff % 50 !== 0) return -1;
  return diff / 50;
}

// Get discount slot info for debugging
function getDiscountPriceSlotsInfo(packageId = null) {
  if (packageId) {
    const key = String(packageId);
    if (!discountPriceSlots[key]) {
      return { packageId, totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS, usedSlots: 0, slots: {} };
    }
    const slots = discountPriceSlots[key];
    const usedSlots = Object.keys(slots).length;
    return {
      packageId,
      totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
      usedSlots: usedSlots,
      availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - usedSlots,
      slots: slots
    };
  }
  
  // Barcha poollarni ko'rsatish
  const allPools = {};
  for (const key in discountPriceSlots) {
    const slots = discountPriceSlots[key];
    allPools[key] = {
      totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
      usedSlots: Object.keys(slots).length,
      availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - Object.keys(slots).length
    };
  }
  return allPools;
}

// ======================
// 🎯 PREMIUM PRICE SLOT SYSTEM - Dinamik narx tizimi (Chiroyli narxlar)
// ======================
// 3 oy uchun narxlar (masalan, base: 90,000):
// ┌─────────────────────────────────────────────────────────────────┐
// │ Birinchi 10 slot (round narxlar):                               │
// │ Slot 0:  90,000 | Slot 1:  89,900 | Slot 2:  89,800 | Slot 3:  89,700 │
// │ Slot 4:  89,600 | Slot 5:  89,500 | Slot 6:  89,400 | Slot 7:  89,300 │
// │ Slot 8:  89,200 | Slot 9:  89,100                                │
// ├─────────────────────────────────────────────────────────────────┤
// │ Ikkinchi 10 slot (50 so'm offset):                              │
// │ Slot 10: 89,950 | Slot 11: 89,850 | Slot 12: 89,750 | Slot 13: 89,650 │
// │ Slot 14: 89,550 | Slot 15: 89,450 | Slot 16: 89,350 | Slot 17: 89,250 │
// │ Slot 18: 89,150 | Slot 19: 89,050                                │
// └─────────────────────────────────────────────────────────────────┘

// In-memory premium price slot tracker: { months: { slotIndex: { orderId, createdAt } } }
const premiumPriceSlots = {};

// Get available premium price slot for a month duration
function getAvailablePremiumPriceSlot(months) {
  const now = Date.now();
  
  // Initialize if not exists
  if (!premiumPriceSlots[months]) {
    premiumPriceSlots[months] = {};
  }
  
  const slots = premiumPriceSlots[months];
  
  // Clean up expired slots
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (slots[i]) {
      const elapsed = now - slots[i].createdAt;
      if (elapsed > PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
        console.log(`🧹 Premium Slot ${i} tozalandi (expired): months=${months}`);
        delete slots[i];
      }
    }
  }
  
  // Find first available slot (0-indexed)
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (!slots[i]) {
      return i;
    }
  }
  
  // All slots are taken
  return -1;
}

// Reserve a premium price slot
function reservePremiumPriceSlot(months, slotIndex, orderId) {
  if (!premiumPriceSlots[months]) {
    premiumPriceSlots[months] = {};
  }
  
  premiumPriceSlots[months][slotIndex] = {
    orderId: orderId,
    createdAt: Date.now()
  };
  
  console.log(`🎯 Premium Slot ${slotIndex} rezerv qilindi: months=${months}, orderId=${orderId}`);
}

// Release a premium price slot by orderId
function releasePremiumPriceSlotByOrderId(orderId) {
  for (const months in premiumPriceSlots) {
    for (const slotIndex in premiumPriceSlots[months]) {
      if (premiumPriceSlots[months][slotIndex].orderId === orderId) {
        console.log(`🔓 Premium Slot ${slotIndex} bo'shatildi: months=${months}, orderId=${orderId}`);
        delete premiumPriceSlots[months][slotIndex];
        return true;
      }
    }
  }
  return false;
}

// Calculate premium price for a slot - CHIROYLI NARX TIZIMI
// Birinchi 10 slot (0-9): round narxlar (100 so'm step)
// Ikkinchi 10 slot (10-19): 50 so'm offset bilan (100 so'm step)
function calculatePremiumSlotPrice(months, slotIndex) {
  const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
  const basePrice = priceMap[months] || 0;
  
  if (slotIndex < 10) {
    // Birinchi 10 slot: base, base-100, base-200... base-900
    return basePrice - (slotIndex * 100);
  } else {
    // Ikkinchi 10 slot: base-50, base-150, base-250... base-950
    return basePrice - 50 - ((slotIndex - 10) * 100);
  }
}

// Get current premium slot info for debugging
function getPremiumPriceSlotsInfo(months) {
  if (!premiumPriceSlots[months]) {
    return { totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS, usedSlots: 0, slots: {} };
  }
  
  const slots = premiumPriceSlots[months];
  const usedSlots = Object.keys(slots).length;
  
  return {
    totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
    usedSlots: usedSlots,
    availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - usedSlots,
    slots: slots
  };
}

// ======================
// 🎁 GIFT PRICE SLOT SYSTEM - Dinamik narx tizimi (Chiroyli narxlar)
// ======================
// 10 ta slot: birinchi 5 ta round narxlar, keyingi 5 ta 50 so'm offset
// Masalan, 15 stars gift = 4,000 so'm base:
// ┌─────────────────────────────────────────────────────────────────┐
// │ Birinchi 5 slot (round narxlar - 100 so'm step):                │
// │ Slot 0: 4,000 | Slot 1: 3,900 | Slot 2: 3,800 | Slot 3: 3,700   │
// │ Slot 4: 3,600                                                    │
// ├─────────────────────────────────────────────────────────────────┤
// │ Ikkinchi 5 slot (50 so'm offset - 100 so'm step):               │
// │ Slot 5: 3,950 | Slot 6: 3,850 | Slot 7: 3,750 | Slot 8: 3,650   │
// │ Slot 9: 3,550                                                    │
// └─────────────────────────────────────────────────────────────────┘
const GIFT_SLOT_CONFIG = {
  MAX_SLOTS: 10,           // Maksimum parallel gift orderlar (0-9)
  PRICE_STEP: 100,         // Har bir slot uchun 100 so'm farq
  SLOT_TIMEOUT: 5 * 60 * 1000, // 5 daqiqa (ms)
};

// In-memory gift price slot tracker: { giftStars: { slotIndex: { orderId, createdAt } } }
const giftPriceSlots = {};

// Get available gift price slot for a gift stars amount
function getAvailableGiftPriceSlot(giftStars) {
  const now = Date.now();
  
  // Initialize if not exists
  if (!giftPriceSlots[giftStars]) {
    giftPriceSlots[giftStars] = {};
  }
  
  const slots = giftPriceSlots[giftStars];
  
  // Clean up expired slots
  for (let i = 0; i < GIFT_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (slots[i]) {
      const elapsed = now - slots[i].createdAt;
      if (elapsed > GIFT_SLOT_CONFIG.SLOT_TIMEOUT) {
        console.log(`🧹 Gift Slot ${i} tozalandi (expired): stars=${giftStars}`);
        delete slots[i];
      }
    }
  }
  
  // Find first available slot (0-indexed)
  for (let i = 0; i < GIFT_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (!slots[i]) {
      return i;
    }
  }
  
  // All slots are taken
  return -1;
}

// Reserve a gift price slot
function reserveGiftPriceSlot(giftStars, slotIndex, orderId) {
  if (!giftPriceSlots[giftStars]) {
    giftPriceSlots[giftStars] = {};
  }
  
  giftPriceSlots[giftStars][slotIndex] = {
    orderId: orderId,
    createdAt: Date.now()
  };
  
  console.log(`🎯 Gift Slot ${slotIndex} rezerv qilindi: stars=${giftStars}, orderId=${orderId}`);
}

// Release a gift price slot by orderId
function releaseGiftPriceSlotByOrderId(orderId) {
  for (const giftStars in giftPriceSlots) {
    for (const slotIndex in giftPriceSlots[giftStars]) {
      if (giftPriceSlots[giftStars][slotIndex].orderId === orderId) {
        console.log(`🔓 Gift Slot ${slotIndex} bo'shatildi: stars=${giftStars}, orderId=${orderId}`);
        delete giftPriceSlots[giftStars][slotIndex];
        return true;
      }
    }
  }
  return false;
}

// Calculate gift price for a slot - CHIROYLI NARX TIZIMI
// Birinchi 5 slot (0-4): round narxlar - base, base-100, base-200, base-300, base-400
// Ikkinchi 5 slot (5-9): 50 so'm offset - base-50, base-150, base-250, base-350, base-450
function calculateGiftSlotPrice(giftStars, slotIndex) {
  const basePrice = GIFT_PRICE_MAP[giftStars] || 0;
  
  if (slotIndex < 5) {
    // Birinchi 5 slot: base, base-100, base-200, base-300, base-400
    return basePrice - (slotIndex * GIFT_SLOT_CONFIG.PRICE_STEP);
  } else {
    // Ikkinchi 5 slot: base-50, base-150, base-250, base-350, base-450
    return basePrice - 50 - ((slotIndex - 5) * GIFT_SLOT_CONFIG.PRICE_STEP);
  }
}

// Get current gift slot info for debugging
function getGiftPriceSlotsInfo(giftStars) {
  if (!giftPriceSlots[giftStars]) {
    return { totalSlots: GIFT_SLOT_CONFIG.MAX_SLOTS, usedSlots: 0, slots: {} };
  }
  
  const slots = giftPriceSlots[giftStars];
  const usedSlots = Object.keys(slots).length;
  
  return {
    totalSlots: GIFT_SLOT_CONFIG.MAX_SLOTS,
    usedSlots: usedSlots,
    availableSlots: GIFT_SLOT_CONFIG.MAX_SLOTS - usedSlots,
    slots: slots
  };
}

// ======================
// 🤖 TELEGRAM BOT - Buyurtmalar kanaliga xabar yuborish
// ======================
const BOT_TOKEN = process.env.BOT_TOKEN;

function parseTelegramChatId(envVal, fallback) {
  if (envVal === undefined || envVal === null || String(envVal).trim() === '') return fallback;
  const n = Number(String(envVal).trim());
  return Number.isFinite(n) ? n : fallback;
}

const ORDERS_CHANNEL = parseTelegramChatId(process.env.ORDERS_CHANNEL, -1003360169974);
const ERROR_LOG_CHANNEL_ID = parseTelegramChatId(process.env.ERROR_LOG_CHANNEL_ID, -1003919789850);
const SUBSCRIPTION_CHANNEL = "@StarsxPremium"; // Majburiy obuna / yangiliklar (https://t.me/StarsxPremium)
const WEBAPP_URL = process.env.WEBAPP_URL || "https://starsx.starstg.uz";
let bot = null;
if (BOT_TOKEN) {
  bot = new Telegraf(BOT_TOKEN);
  console.log('✅ Telegram bot initialized for order notifications');
} else {
  console.warn('⚠️ BOT_TOKEN .env da topilmadi - orders channel xabarlar yuborilmaydi');
}

// 🎉 Yangi foydalanuvchiga xush kelibsiz xabari yuborish
async function sendWelcomeMessage(userId, userName) {
  if (!bot || !userId) {
    console.log('❌ Bot ishga tushmagan yoki userId yo\'q, xabar yuborilmadi');
    return;
  }
  try {
    const welcomeText = `🎉 <b>Xush kelibsiz, ${userName || 'do\'stim'}!</b>

✨ <b>StarsJoy</b> — Telegram Stars va Premium xarid qilishning eng qulay va ishonchli platformasi!

📢 Kanalimizga obuna bo'ling va barcha yangiliklar, chegirmalar va maxsus takliflardan xabardor bo'ling!

Stars xarid qilish
Premium sotib olish
Do'stlaringizga Gift yuborish

Barchasi bir joyda — <b>StarsJoy</b>!`;

    await bot.telegram.sendMessage(userId, welcomeText, {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            { text: '�Start', url: 'https://t.me/StarsjoyBot?start=welcome' }
          ],
          
        ]
      }
    });
    console.log(`✅ Xush kelibsiz xabari yuborildi: ${userId} (${userName})`);
  } catch (err) {
    console.error('❌ Xush kelibsiz xabari yuborishda xato:', err.message);
  }
}

// Buyurtmalar kanali xabari yuborish funksiyasi
async function notifyOrdersChannel(message) {
  if (!bot) {
    console.log('❌ Bot ishga tushmagan, xabar yuborilmadi');
    return;
  }
  try {
    await bot.telegram.sendMessage(ORDERS_CHANNEL, message, { parse_mode: 'HTML' });
    console.log('✅ Orders channel ga xabar yuborildi');
  } catch (err) {
    console.error('❌ Orders channel xabari yuborishda xato:', err.message);
  }
}

/** Admin panel: qo'lda premium — ORDERS_CHANNEL (.env) ga BOT_TOKEN orqali */
async function sendManualPremiumSoldChannelMessage(order, plan, adminUser) {
  const token = process.env.BOT_TOKEN;
  const channelId = ORDERS_CHANNEL;
  const adminUsername = adminUser?.username;
  const adminLine = adminUsername
    ? (String(adminUsername).startsWith('@') ? String(adminUsername) : `@${adminUsername}`)
    : 'Admin';
  const rawRecipient = order.recipient_username || order.recipient || "Noma'lum";
  const recipientLine = String(rawRecipient).startsWith('@') ? String(rawRecipient) : `@${rawRecipient}`;
  const miqdorLabel = plan === '1_yil' ? '1 yil (akkauntga kirib)' : '1 oy (akkauntga kirib)';
  const summNum = Number(order.summ) || 0;
  const message =
    `👑 <b>Yangi Premium sotildi!</b>\n\n` +
    `📦 Order: #${order.id}\n` +
    `👤 ${adminLine} -> ${recipientLine}\n` +
    `💫 Miqdor: ${miqdorLabel}\n` +
    `💰 Summa: ${summNum.toLocaleString()} so'm\n` +
    `✅ Status: Yetkazildi`;

  try {
    if (bot) {
      await bot.telegram.sendMessage(channelId, message, { parse_mode: 'HTML' });
      console.log(`✅ Manual premium: orders channel #${order.id}`);
      return;
    }
    if (token) {
      const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: channelId,
          text: message,
          parse_mode: 'HTML',
          disable_web_page_preview: true
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!data.ok) {
        console.error('❌ Manual premium orders channel (API):', data.description || response.status);
      } else {
        console.log(`✅ Manual premium: orders channel (API) #${order.id}`);
      }
      return;
    }
    console.warn("⚠️ Manual premium: BOT_TOKEN yo'q — kanalga xabar yuborilmadi");
  } catch (err) {
    console.error('❌ Manual premium orders channel:', err.message);
  }
}
// ======================
// 🔧 MAINTENANCE MODE (texnik ishlar rejimi)
// ======================
let maintenanceMode = false;
app.get("/api/maintenance", (req, res) => {
  res.json({ maintenance: maintenanceMode });
});
app.post("/api/admin/maintenance", adminAuth, (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: "enabled (true/false) kerak" });
  }
  maintenanceMode = enabled;
  console.log(`🔧 Maintenance mode: ${enabled ? 'YOQILDI ⛔' : 'O\'CHIRILDI ✅'}`);
  res.json({ success: true, maintenance: maintenanceMode });
});

// ======================
// 📢 BROADCAST — Barcha foydalanuvchilarga xabar yuborish (Bot API)
// ======================
app.post("/api/admin/broadcast", adminAuth, async (req, res) => {
  try {
    const { message, parseMode } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Xabar matni kerak" });
    }
    
    // Barcha user_id larni olish
    const usersResult = await pool.query(
      "SELECT DISTINCT user_id FROM users WHERE user_id IS NOT NULL AND user_id != ''"
    );
    
    const users = usersResult.rows;
    const totalUsers = users.length;
    
    if (totalUsers === 0) {
      return res.json({ success: true, sent: 0, failed: 0, total: 0 });
    }
    
    console.log(`📢 Broadcast boshlanmoqda: ${totalUsers} ta foydalanuvchiga`);
    
    let sent = 0;
    let failed = 0;
    const errors = [];
    
    // Bot token orqali yuborish (Telegraf bot ishlamasa ham ishlaydi)
    const botToken = process.env.BOT_TOKEN;
    if (!botToken) {
      return res.status(500).json({ error: "BOT_TOKEN topilmadi" });
    }
    
    // Har bir foydalanuvchiga xabar yuborish
    const BATCH_SIZE = 25;
    const DELAY_MS = 50;
    
    for (let i = 0; i < users.length; i += BATCH_SIZE) {
      const batch = users.slice(i, i + BATCH_SIZE);
      
      const promises = batch.map(async (user) => {
        try {
          const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              chat_id: user.user_id,
              text: message.trim(),
              parse_mode: parseMode || 'HTML',
              disable_web_page_preview: true
            })
          });
          
          const data = await response.json();
          
          if (data.ok) {
            sent++;
            return { success: true, user_id: user.user_id };
          } else {
            failed++;
            // Blocked yoki deleted users
            if (!data.description?.includes('blocked') && !data.description?.includes('deactivated')) {
              errors.push({ user_id: user.user_id, error: data.description });
            }
            return { success: false, user_id: user.user_id, error: data.description };
          }
        } catch (err) {
          failed++;
          return { success: false, user_id: user.user_id, error: err.message };
        }
      });
      
      await Promise.all(promises);
      
      // Rate limit uchun kutish
      if (i + BATCH_SIZE < users.length) {
        await new Promise(resolve => setTimeout(resolve, DELAY_MS));
      }
    }
    
    console.log(`📢 Broadcast tugadi: ${sent}/${totalUsers} yuborildi, ${failed} xato`);
    
    res.json({
      success: true,
      sent,
      failed,
      total: totalUsers,
      errors: errors.slice(0, 10)
    });
    
  } catch (err) {
    console.error("❌ /api/admin/broadcast ERROR:", err);
    res.status(500).json({ error: "Server xatosi", details: err.message });
  }
});

// ======================
// 🔔 NOTIFICATIONS API
// ======================
// Admin: Send notification (global or to specific user)
app.post("/api/admin/notifications", adminAuth, async (req, res) => {
  try {
    const { title, message, type, user_id, is_global } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ error: "title va message kerak" });
    }
    
    const notifType = type || 'info'; // info, success, warning, promo
    
    if (is_global) {
      // Global notification - barcha userlarga
      const result = await pool.query(
        `INSERT INTO notifications (title, message, type, is_global, created_at)
         VALUES ($1, $2, $3, true, NOW())
         RETURNING *`,
        [title, message, notifType]
      );
      console.log(`🔔 Global notification yuborildi: "${title}"`);
      res.json({ success: true, notification: result.rows[0], type: 'global' });
    } else if (user_id) {
      // Specific user notification
      const result = await pool.query(
        `INSERT INTO notifications (user_id, title, message, type, is_global, created_at)
         VALUES ($1, $2, $3, $4, false, NOW())
         RETURNING *`,
        [user_id, title, message, notifType]
      );
      console.log(`🔔 Notification yuborildi: user_id=${user_id}, "${title}"`);
      res.json({ success: true, notification: result.rows[0], type: 'personal' });
    } else {
      return res.status(400).json({ error: "user_id yoki is_global kerak" });
    }
  } catch (err) {
    console.error("❌ /api/admin/notifications ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Get user notifications (personal + global)
app.get("/api/notifications/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    
    // Get personal + global notifications
    const result = await pool.query(
      `SELECT * FROM notifications 
       WHERE user_id = $1 OR is_global = true
       ORDER BY created_at DESC
       LIMIT 50`,
      [user_id]
    );
    
    res.json({ success: true, notifications: result.rows });
  } catch (err) {
    console.error("❌ /api/notifications ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Get unread count
app.get("/api/notifications/unread/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    
    // Count unread personal + global notifications
    // For global notifications, we need to track read status per user
    // Simple approach: count notifications created after user's last read time
    const result = await pool.query(
      `SELECT COUNT(*) as count FROM notifications 
       WHERE (user_id = $1 OR is_global = true) AND is_read = false`,
      [user_id]
    );
    
    res.json({ success: true, unread_count: parseInt(result.rows[0].count) || 0 });
  } catch (err) {
    console.error("❌ /api/notifications/unread ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Mark notification as read
app.post("/api/notifications/:id/read", telegramAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query(
      `UPDATE notifications SET is_read = true WHERE id = $1`,
      [id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("❌ /api/notifications/read ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Mark all as read for user
app.post("/api/notifications/read-all/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    
    await pool.query(
      `UPDATE notifications SET is_read = true 
       WHERE (user_id = $1 OR is_global = true) AND is_read = false`,
      [user_id]
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("❌ /api/notifications/read-all ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Admin: Get all notifications
app.get("/api/admin/notifications", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100`
    );
    res.json({ success: true, notifications: result.rows });
  } catch (err) {
    console.error("❌ /api/admin/notifications GET ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// Admin: Delete notification
app.delete("/api/admin/notifications/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(`DELETE FROM notifications WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("❌ /api/admin/notifications DELETE ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ======================
// 🎁 ADMIN: PROMO CODES
// ======================
app.get("/api/admin/promocodes", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM promocodes ORDER BY created_at DESC`);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET /api/admin/promocodes ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

app.post("/api/admin/promocodes", adminAuth, async (req, res) => {
  try {
    const { code, target_type, target_amount, discount_percent, usage_limit } = req.body;
    
    // Use manually provided code from AdminPanel
    let finalCode = code;
    if (!finalCode) {
      // Fallback in case it's not provided
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      finalCode = '';
      for (let i = 0; i < 6; i++) {
        finalCode += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    }

    const targAmt = target_amount ? parseInt(target_amount) : null;
    
    await pool.query(
      `INSERT INTO promocodes (code, target_type, target_amount, discount_percent, usage_limit)
       VALUES ($1, $2, $3, $4, $5)`,
      [finalCode, target_type, targAmt, discount_percent, usage_limit || 1]
    );

    res.json({ success: true, message: "Promokod yaratildi", code: finalCode });
  } catch (err) {
    console.error("❌ POST /api/admin/promocodes ERROR:", err);
    if(err.code === '23505') return res.status(400).json({ error: "Bunday kod allaqachon mavjud" });
    res.status(500).json({ error: "Server xatosi" });
  }
});

app.delete("/api/admin/promocodes/:code", adminAuth, async (req, res) => {
  try {
    const { code } = req.params;
    await pool.query(`DELETE FROM promocodes WHERE code = $1`, [code]);
    res.json({ success: true, message: "O'chirildi" });
  } catch (err) {
    res.status(500).json({ error: "Server xatosi" });
  }
});

app.put("/api/admin/promocodes/:code/toggle", adminAuth, async (req, res) => {
  try {
    const { code } = req.params;
    const result = await pool.query(
      `UPDATE promocodes SET is_active = NOT is_active WHERE code = $1 RETURNING is_active`,
      [code]
    );
    if(result.rows.length === 0) return res.status(404).json({error: "Pramakod topilmadi"});
    res.json({ success: true, is_active: result.rows[0].is_active });
  } catch (err) {
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ======================
// 🛡️ GLOBAL ERROR HANDLERS — Process crash oldini olish
// ======================
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
  // Process'ni crash qilmaslik
});

process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught Exception:', err);
  // Critical xatolarda log qilib davom etish
});

// ======================
// Postgresga ulanish
// ======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, // Maksimum connection soni (default 10)
  idleTimeoutMillis: 30000, // Bo'sh connection 30s da yopiladi
  connectionTimeoutMillis: 10000, // Connection olish uchun 10s kutish
  allowExitOnIdle: false, // Idle bo'lganda exit qilmaslik
});

// Pool error handler
pool.on('error', (err) => {
  console.error('❌ Database pool xatosi:', err.message);
});

// Pool connect handler
pool.on('connect', () => {
  console.log('📊 Database connection ochildi');
});
// ======================
// Jadval yaratish
// ======================
// 📦 UNIFIED ORDERS TABLE (yangi optimallashtirilgan jadval)
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      order_id TEXT NOT NULL,
      owner_user_id TEXT,
      recipient_username TEXT,
      recipient TEXT,
      order_type VARCHAR(32) NOT NULL,
      type_amount INTEGER NOT NULL,
      summ INTEGER NOT NULL,
      payment_method VARCHAR(32),
      payment_status VARCHAR(32) DEFAULT 'pending',
      status VARCHAR(32) DEFAULT 'pending',
      transaction_id TEXT,
      gift_id TEXT,
      gift_anonymous BOOLEAN DEFAULT false,
      gift_comment TEXT,
      applied_promocode TEXT,
      discount_amount INTEGER DEFAULT 0,
      expired_notified BOOLEAN DEFAULT false,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);

  console.log("✅ Table 'orders' ready (unified)");
})();

// ======================
// 🎁 PROMOCODES TABLE (Chegirmalar uchun)
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS promocodes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      target_type VARCHAR(32) NOT NULL, -- 'stars', 'gift', 'premium', yoki 'all'
      target_amount INTEGER, -- ma'lum bir miqdor uchun. NULL = barchasi uchun
      discount_percent INTEGER NOT NULL, -- fayz, masalan: 10
      usage_limit INTEGER DEFAULT 1, -- Necha marta ishlashi mumkin
      used_count INTEGER DEFAULT 0, -- Hozirgacha necha marta ishlatilgani
      is_active BOOLEAN DEFAULT true, -- Admin vaqtinchalik o'chirishi mumkin
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'promocodes' ready");
})();

// ======================
// 🆕 REFERRAL SYSTEM TABLES
// ======================
(async () => {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT,
      username TEXT UNIQUE NOT NULL,
      user_id TEXT UNIQUE,
      referral_code TEXT UNIQUE,
      referrer_user_id TEXT,
      referral_balance INTEGER DEFAULT 0,
      total_earnings INTEGER DEFAULT 0, 
      total_referrals INTEGER DEFAULT 0,
      subscribe_user BOOLEAN DEFAULT false,
      language VARCHAR(5) DEFAULT 'uz',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);

  console.log("✅ Table 'users' ready (yangi tuzilma)");
})();
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS referral_earnings (
      id SERIAL PRIMARY KEY,
      referrer_username TEXT NOT NULL,
      referee_username TEXT NOT NULL,
      earned_stars INTEGER,
      triggered_by_transaction_id INTEGER,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'referral_earnings' ready");
})();

// ======================
// 📈 DATABASE INDEXES — Query tezligini oshirish
// ======================
(async () => {
  try {
    // Orders jadvaliga indekslar
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_owner_user_id ON orders(owner_user_id)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_status ON orders(status)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_payment_status ON orders(payment_status)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_summ ON orders(summ)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_order_type ON orders(order_type)`);
    // Composite index for leaderboard query
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_leaderboard ON orders(owner_user_id, status, order_type, summ)`);
    
    // Users jadvaliga indekslar
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_user_id ON users(user_id)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username ON users(username)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_referrer_user_id ON users(referrer_user_id)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_referral_code ON users(referral_code)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_subscribe ON users(subscribe_user)`);
    
    // Notifications jadvaliga indekslar
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)`);
    await pool.query(`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_is_read ON notifications(is_read)`);
    
    console.log("✅ Database indexes created");
  } catch (err) {
    // CONCURRENTLY ishlatganda xato bo'lishi mumkin, ignore qilamiz
    console.log("⚠️ Some indexes may already exist:", err.message);
  }
})();

// ======================
// 🏷️ DISCOUNT PACKAGES TABLE
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discount_packages (
      id SERIAL PRIMARY KEY,
      stars INTEGER NOT NULL,
      discount_percent INTEGER NOT NULL,
      discounted_price INTEGER NOT NULL,
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent'),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'discount_packages' ready");
})();
// ======================
// 🔔 NOTIFICATIONS TABLE
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id TEXT,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      is_read BOOLEAN DEFAULT false,
      is_global BOOLEAN DEFAULT false,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'notifications' ready");
})();

// ======================
// 📝 REFERRAL VERIFICATION REQUESTS TABLE
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS referral_requests (
      id SERIAL PRIMARY KEY,
      owner_user_id TEXT NOT NULL,
      owner_username TEXT NOT NULL,
      referrer_user_id TEXT NOT NULL,
      referrer_username TEXT NOT NULL,
      subscribe_referrer BOOLEAN DEFAULT false,
      is_accepted BOOLEAN DEFAULT false,
      rejected_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'referral_requests' ready");
})();

// ======================
// 📊 REFERRAL LEADERBOARD (referrer_user_id orqali sanash - faqat subscribe_user = true)
// ======================
app.get("/api/referral/leaderboard", telegramAuth, async (req, res) => {
  try {
    const { user_id, period } = req.query;
    
    // Period filter: daily (bugun), weekly (7 kun orqaga), monthly (30 kun orqaga)
    // Do'stning ro'yxatdan o'tgan sanasi (created_at) bo'yicha filter
    let dateFilter = "";
    if (period === "daily") {
      // Bugun: 00:00:00 dan 23:59:59 gacha
      dateFilter = "AND u1.created_at >= CURRENT_DATE AND u1.created_at < CURRENT_DATE + INTERVAL '1 day'";
    } else if (period === "weekly") {
      // Bugundan 7 kun orqaga
      dateFilter = "AND u1.created_at >= CURRENT_DATE - INTERVAL '6 days'";
    } else if (period === "monthly") {
      // Bugundan 30 kun orqaga
      dateFilter = "AND u1.created_at >= CURRENT_DATE - INTERVAL '29 days'";
    }
    
    // Top 10 users by referral count (faqat kanalga obuna bo'lgan do'stlarni sanash)
    const top10 = (await pool.query(
      `WITH referral_counts AS (
        SELECT 
          u2.username,
          u2.name,
          u2.user_id,
          COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
          COUNT(*) as referrals
        FROM users u1
        JOIN users u2 ON u1.referrer_user_id = u2.user_id
        WHERE u1.referrer_user_id IS NOT NULL
          AND u1.subscribe_user = true
          ${dateFilter}
        GROUP BY u2.user_id, u2.username, u2.name
      )
      SELECT 
        username,
        name,
        user_id,
        nickname,
        referrals,
        ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
      FROM referral_counts
      ORDER BY referrals DESC
      LIMIT 10`
    )).rows;
    let me = null;
    if (user_id) {
      const userRow = (await pool.query(
        `WITH referral_counts AS (
          SELECT 
            u2.user_id,
            u2.username,
            u2.name,
            COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
            COUNT(*) as referrals
          FROM users u1
          JOIN users u2 ON u1.referrer_user_id = u2.user_id
          WHERE u1.referrer_user_id IS NOT NULL
            AND u1.subscribe_user = true
            ${dateFilter}
          GROUP BY u2.user_id, u2.username, u2.name
        ),
        ranked AS (
          SELECT 
            user_id,
            username,
            name,
            nickname,
            referrals,
            ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
          FROM referral_counts
        )
        SELECT * FROM ranked WHERE user_id = $1`, [user_id]
      )).rows[0];
      
      if (userRow) {
        me = userRow;
      } else {
        // User hech kimni taklif qilmagan (yoki do'stlari hali obuna bo'lmagan)
        const userData = (await pool.query('SELECT username, name FROM users WHERE user_id = $1', [user_id])).rows[0];
        me = { user_id, username: userData?.username, name: userData?.name, nickname: userData?.name || userData?.username || 'Foydalanuvchi', referrals: 0, rank: null };
      }
    }
    res.json({ top10, me });
  } catch (err) {
    console.error("❌ REFERRAL LEADERBOARD ERROR:", err);
    res.status(500).json({ error: "Leaderboard error" });
  }
});
// ======================
// 👥 MENING DO'STLARIM (taklif qilingan foydalanuvchilar ro'yxati)
// ======================
app.get("/api/referral/my-friends/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) return res.status(400).json({ error: "user_id kerak" });
    
    // Barcha do'stlarni olish (aktiv va inaktiv)
    const friends = await pool.query(
      `SELECT 
        name,
        username,
        user_id,
        subscribe_user,
        created_at
       FROM users
       WHERE referrer_user_id = $1
       ORDER BY subscribe_user DESC, created_at DESC`,
      [user_id]
    );
    
    // Kutilayotgan (hali obuna bo'lmagan) do'stlar soni
    const pendingCount = await pool.query(
      `SELECT COUNT(*) as count FROM users
       WHERE referrer_user_id = $1 AND subscribe_user = false`,
      [user_id]
    );
    
    res.json({ 
      friends: friends.rows,
      pending_count: parseInt(pendingCount.rows[0].count) || 0
    });
  } catch (err) {
    console.error("❌ MY FRIENDS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// 📊 REFERRAL STATS (referrer_user_id orqali do'stlar sonini sanash)
// ======================
app.get("/api/referral/friends-count/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) return res.status(400).json({ error: "user_id kerak" });
    // Faqat kanalga obuna bo'lgan (aktiv) do'stlar sonini sanash
    const result = await pool.query(
      `SELECT COUNT(*) as friends_count
       FROM users
       WHERE referrer_user_id = $1
         AND subscribe_user = true`,
      [user_id]
    );
    res.json({ friends_count: parseInt(result.rows[0].friends_count) || 0 });
  } catch (err) {
    console.error("❌ FRIENDS COUNT ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// 3️⃣ Backend holati
// ======================
app.get("/api/status", (req, res) => {
  res.json({ message: "Sayt aktiv holatda ✅" });
});

// ======================
// 🎯 INTERNAL: Slot bo'shatish (balanceChecker uchun)
// ======================
app.post("/api/internal/release-slot", internalAuth, (req, res) => {
  const { orderId } = req.body;
  
  if (!orderId) {
    return res.status(400).json({ error: "orderId kerak" });
  }
  
  const released = releasePriceSlotByOrderId(orderId);
  
  res.json({ 
    success: true, 
    released: released,
    message: released ? "Slot bo'shatildi" : "Slot topilmadi"
  });
});

// ======================
// 🎯 INTERNAL: Slot info (debugging uchun)
// ======================
app.get("/api/internal/slots-info", internalAuth, (req, res) => {
  const info = getPriceSlotsInfo();
  res.json(info);
});

// ======================
// 🎯 PUBLIC: Narx olish (frontend uchun)
// ======================
app.get("/api/stars/price/:stars", async (req, res) => {
  const stars = parseInt(req.params.stars);
  
  if (!stars || isNaN(stars) || stars < 50 || stars > 10000) {
    return res.status(400).json({ error: "Stars 50 dan 10000 gacha bo'lishi kerak" });
  }
  
  // 🛡️ Gift/Premium pending orderlar narxlarini olish (conflict uchun)
  let conflictPrices = new Set();
  try {
    const giftPremiumPrices = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium') 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'`
    );
    conflictPrices = new Set(giftPremiumPrices.rows.map(r => r.summ));
  } catch (err) {
    console.error('⚠️ Conflict prices olishda xato:', err.message);
  }
  
  // Bo'sh slot topish (conflict tekshirish bilan)
  let slotIndex = -1;
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    const baseSlot = getAvailablePriceSlot(stars);
    if (baseSlot === -1) break;
    
    // Slotni tekshirish
    const key = String(stars);
    if (priceSlots[key] && priceSlots[key][i]) {
      const elapsed = Date.now() - priceSlots[key][i].createdAt;
      if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
        continue; // Slot band
      }
    }
    
    // Bo'sh slot, narxni tekshirish
    const candidatePrice = calculateSlotPrice(stars, i);
    if (conflictPrices.has(candidatePrice)) {
      continue; // Gift/Premium bilan conflict
    }
    
    slotIndex = i;
    break;
  }
  
  if (slotIndex === -1) {
    return res.json({ 
      available: false,
      message: "Hozirda juda ko'p buyurtmalar mavjud"
    });
  }
  
  const maxPrice = stars * STARS_PRICE_PER_UNIT; // Max narx: stars * 240
  const price = calculateSlotPrice(stars, slotIndex);
  const minPrice = maxPrice - 950; // 20 ta slot (0-19), oxirgisi maxPrice - 950
  const slotsInfo = getPriceSlotsInfo(stars);
  
  res.json({
    available: true,
    stars: stars,
    maxPrice: maxPrice,
    minPrice: minPrice,
    price: price,
    currentPrice: price,
    slotIndex: slotIndex,
    availableSlots: slotsInfo.availableSlots || PRICE_SLOT_CONFIG.MAX_SLOTS
  });
});

// ======================
// 6️⃣ Admin panel - barcha transactionlarni olish (faqat stars)
// ======================
app.get("/api/transactions/all", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.id,
        o.order_id,
        o.owner_user_id,
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.type_amount AS stars,
        o.summ AS amount,
        o.status,
        o.payment_status,
        o.transaction_id,
        o.created_at,
        o.order_type
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.order_type = 'stars'
      ORDER BY o.id DESC
    `);
    
    // Status mapping: completed → stars_sent
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'stars_sent' : row.status
    }));
    
    res.json(mapped);
  } catch (err) {
    console.error("❌ /api/transactions/all ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 2️⃣ Status bo‘yicha filter
// ======================
app.get("/api/transactions/status/:status", adminAuth, async (req, res) => {
  let { status } = req.params;
  
  // Legacy status mapping: frontend "stars_sent" yuborsa, DB da "completed" qidiramiz
  const dbStatus = status === 'stars_sent' ? 'completed' : status;
  
  try {
    const result = await pool.query(
      `SELECT 
        o.id,
        o.order_id,
        o.owner_user_id,
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.type_amount AS stars,
        o.summ AS amount,
        o.status,
        o.payment_status,
        o.transaction_id,
        o.created_at,
        o.order_type
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.status = $1 AND o.order_type = 'stars'
      ORDER BY o.id DESC`,
      [dbStatus]
    );
    
    // Status mapping: completed → stars_sent
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'stars_sent' : row.status
    }));
    
    res.json(mapped);
  } catch (err) {
    console.error("❌ /api/transactions/status ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 3️⃣ Transaction status update
// ======================
app.patch("/api/transactions/update/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const result = await pool.query(
      "UPDATE orders SET status=$1 WHERE id=$2 RETURNING *",
      [status, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Transaction not found" });
    res.json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// =================================================
// 1️⃣ Telegram userni qidirish —— RobynHood API versiyasi
// =================================================
app.post("/api/search", searchLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("=== 🔍 /api/search (RobynHood) boshlandi ===");
    let { username } = req.body;
    console.log("📥 Keldi username:", username);
    if (!username) {
      return res.status(400).json({ error: "username kerak" });
    }
    const cleanUsername = username.startsWith("@")
      ? username.slice(1)
      : username;
    console.log("🧹 Tozalangan username:", cleanUsername);
    // 🟦 RobynHood API ga so‘rov yuboramiz
    console.log("🌐 RobynHood API'ga so‘rov yuborilmoqda...");
    const response = await fetch("https://robynhood.parssms.info/api/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY, // bu yerga API key qo'yiladi
        "accept": "application/json",
      },
      body: JSON.stringify({
        product_type: "stars",
        query: cleanUsername,
        quantity: "50",
      }),
    });
    console.log("📡 Javob status kodi:", response.status);
    const text = await response.text();
    console.log("📦 API xom javob:", text);
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error("❌ JSON parse xato:", err);
      return res.status(500).json({
        error: "API noto'g'ri format qaytardi",
        raw: text,
      });
    }
    console.log("🔍 JSON parse bo‘ldi:", data);
    if (!data.ok || !data.found) {
      return res.status(404).json({
        error: "Foydalanuvchi topilmadi",
        details: data,
      });
    }
    const found = data.found;
    const fullName = found.name || cleanUsername;
    const recipient = found.recipient;
    const photoHTML = found.photo || "";
    // HTML <img ...> dan src URL ajratamiz
    const match = photoHTML.match(/src="([^"]+)"/);
    const imageUrl = match ? match[1] : null;
    console.log("👤 Foydalanuvchi:", fullName);
    console.log("🖼️ Rasm URL:", imageUrl);
    console.log("🆔 Recipient ID:", recipient);
    return res.json({
      username: cleanUsername,
      fullName: fullName,
      imageUrl: imageUrl,
      recipient: recipient, // ⚠ MUHIM — purchase uchun shu kerak
    });
  } catch (err) {
    console.error("💥 Server xato:", err);
    return res.status(500).json({
      error: "Serverda xatolik",
      details: err.message,
    });
  }
});

// ======================
// 🎁 PROMOCODE CHECK
// ======================
app.post("/api/promocode/check", telegramAuth, async (req, res) => {
  try {
    const { code, type, amount, price } = req.body;
    // type: 'stars', 'gift', 'premium' vs target_type (barchasi uchun 'all')
    const userId = req.telegramUser?.id ? String(req.telegramUser.id) : null;

    if (!code || !type || !price) {
      return res.status(400).json({ error: "Ma'lumot to'liq emas" });
    }

    const { rows } = await pool.query(`SELECT * FROM promocodes WHERE code = $1`, [code]);
    if (rows.length === 0) return res.status(404).json({ error: "Bunday promokod mavjud emas" });

    const promo = rows[0];

    // Tekshiruvlar
    if (!promo.is_active) return res.status(400).json({ error: "Ushbu promokod faol emas" });
    if (promo.used_count >= promo.usage_limit) return res.status(400).json({ error: "Ushbu promokodning muddati tugagan" });
    
    // Type tekshiruvi: 'all' bo'lsa hammaga ishlaydi. 
    if (promo.target_type !== 'all' && promo.target_type !== type) {
      return res.status(400).json({ error: `Ushbu promokod faqat ${promo.target_type} uchun mo'ljallangan` });
    }

    // Amount tekshiruvi (agar ko'rsatilgan bo'lsa)
    if (promo.target_amount !== null && promo.target_amount !== parseInt(amount)) {
      return res.status(400).json({ error: `Ushbu promokod faqat ${promo.target_amount} ${type} uchun mo'ljallangan` });
    }

    // Foydalanuvchi oldin ishlatganligini tekshirish (1 marta ruxsat berish)
    if (userId) {
      const userUsage = await pool.query(
        `SELECT id FROM orders WHERE owner_user_id = $1 AND applied_promocode = $2 AND status IN ('success', 'pending', 'processing') LIMIT 1`,
        [userId, code]
      );
      if (userUsage.rows.length > 0) {
        return res.status(400).json({ error: "Siz ushbu promokoddan foydalangansiz yoki faol to'lovingiz bor" });
      }
    }

    // Hammasi joyida, narxni hisoblaymiz
    const discountAmount = Math.floor(price * (promo.discount_percent / 100));
    const newPrice = price - discountAmount;

    res.json({
      success: true,
      discount_percent: promo.discount_percent,
      discount_amount: discountAmount,
      new_price: newPrice,
      message: `${promo.discount_percent}% chegirma qabul qilindi!`
    });

  } catch(err) {
    console.error("❌ /api/promocode/check ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});


// ======================
// 2️⃣ Order yaratish — YANGI orders jadvaliga yozadi
// ======================
app.post("/api/order", orderLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, recipient, stars, amount: requestedAmount, discount_package_id, applied_promocode } = req.body;
    
    // Telegram userId orqali pending orderlar sonini tekshirish
    const maxPendingOrders = 3;
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    if (tgUserId) {
        const activeOrdersRes = await pool.query(
          `SELECT COUNT(*) as count FROM orders WHERE owner_user_id = $1 AND status = 'pending' AND payment_status = 'pending'`,
          [tgUserId]
        );
        if (parseInt(activeOrdersRes.rows[0].count) >= maxPendingOrders) {
          return res.status(429).json({ error: "Sizda to'lanmagan buyurtmalar mavjud. Iltimos oldin ularni to'lang yoki biroz kuting." });
        }
    }

    // ⚠️ Endi recipient majburiy!
    if (!username || !recipient || !stars) {
      return res.status(400).json({
        error: "username, recipient, stars kerak"
      });
    }
    // 🛡️ SECURITY: Stars miqdorini tekshirish (integer, 50-10000)
    const starsNum = parseInt(stars);
    if (!Number.isInteger(starsNum) || starsNum < 50 || starsNum > 10000) {
      return res.status(400).json({
        error: "Stars miqdori 50 dan 10000 gacha bo'lishi kerak"
      });
    }
    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;

    // 🏷️ CHEGIRMA PAKETI BILAN BUYURTMA
    let amount;
    let useDiscountSlot = false;
    let discountPackage = null;
    let discountSlotIndex = -1;
    
    if (discount_package_id) {
      // Chegirma paketi orqali buyurtma
      const discountCheck = await pool.query(
        "SELECT * FROM discount_packages WHERE id = $1 AND stars = $2 AND is_active = true",
        [discount_package_id, starsNum]
      );
      
      if (discountCheck.rows.length > 0) {
        discountPackage = discountCheck.rows[0];
        
        // 🛡️ Slot tizimi - har bir chegirma paketi uchun alohida 20 ta slot
        
        for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
          // Slot band bo'lsa, keyingisiga o'tish
          if (discountPriceSlots[discountPackage.id] && discountPriceSlots[discountPackage.id][i]) {
            const elapsed = Date.now() - discountPriceSlots[discountPackage.id][i].createdAt;
            if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
              continue;
            }
            // Expired slot - tozalash
            delete discountPriceSlots[discountPackage.id][i];
          }
          
          // Bo'sh slot topildi
          discountSlotIndex = i;
          amount = calculateDiscountSlotPrice(discountPackage.discounted_price, i);
          break;
        }
        
        if (discountSlotIndex === -1) {
          console.log(`⚠️ Chegirma paketi slotlari band: packageId=${discountPackage.id}`);
          return res.status(503).json({
            error: "Bu chegirma paketi uchun juda ko'p buyurtmalar mavjud. Iltimos, 1-2 daqiqadan keyin qayta urinib ko'ring.",
            code: "SLOTS_FULL"
          });
        }
        
        useDiscountSlot = true;
        console.log(`🏷️ Chegirma paketi: ${starsNum} stars, Slot ${discountSlotIndex} = ${amount} so'm (base: ${discountPackage.discounted_price})`);
        
        // 🎯 MUHIM: Slotni DARHOL rezerv qilish (race condition oldini olish)
        const tempReservationId = `temp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
        if (!discountPriceSlots[discountPackage.id]) {
          discountPriceSlots[discountPackage.id] = {};
        }
        discountPriceSlots[discountPackage.id][discountSlotIndex] = {
          orderId: tempReservationId,
          createdAt: Date.now()
        };
      }
    }
    
    // 🎯 ODDIY STARS BUYURTMA (chegirma yo'q)
    let priceSlotIndex = -1;
    
    if (!useDiscountSlot) {
      // 🛡️ Slot tizimi - har bir stars miqdori uchun alohida 20 ta slot
      // Har bir slot unique narx beradi (-50 so'm step)
      
      // Avval priceSlots ni bazadan sinxronlashtirish
      if (!priceSlots[String(starsNum)]) {
        priceSlots[String(starsNum)] = {};
      }
      
      // Bazadagi pending orderlarni tekshirish va slot tizimiga yuklash
      const pendingOrders = await pool.query(
        `SELECT id, summ, created_at FROM orders 
         WHERE order_type = 'stars' AND type_amount = $1 
         AND status = 'pending' AND payment_status = 'pending'
         AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'`,
        [starsNum]
      );
      
      // Bazadagi pending orderlar uchun slotlarni band qilish (yangi formula)
      for (const order of pendingOrders.rows) {
        const maxPrice = starsNum * STARS_PRICE_PER_UNIT;
        const diff = maxPrice - order.summ;
        
        // Yangi formula: diff = slotIndex * 50
        let slotIdx = -1;
        if (diff >= 0 && diff <= 950 && diff % 50 === 0) {
          slotIdx = diff / 50;
        }
        
        if (slotIdx >= 0 && slotIdx < 20 && !priceSlots[String(starsNum)][slotIdx]) {
          priceSlots[String(starsNum)][slotIdx] = {
            orderId: order.id,
            createdAt: new Date(order.created_at).getTime()
          };
        }
      }
      
      // 🛡️ Gift/Premium pending orderlar narxlarini olish (conflict uchun)
      const giftPremiumPrices = await pool.query(
        `SELECT DISTINCT summ FROM orders 
         WHERE order_type IN ('gift', 'premium') 
         AND status = 'pending' AND payment_status = 'pending'
         AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'`
      );
      const conflictPrices = new Set(giftPremiumPrices.rows.map(r => r.summ));
      
      // Bo'sh slot topish (Gift/Premium bilan conflict tekshirish bilan)
      for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
        // Slot band bo'lsa, tekshirish
        if (priceSlots[String(starsNum)][i]) {
          const elapsed = Date.now() - priceSlots[String(starsNum)][i].createdAt;
          if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
            continue; // Slot hali band
          }
          // Expired slot - tozalash
          delete priceSlots[String(starsNum)][i];
        }
        
        // Bo'sh slot topildi, narxni hisoblash
        const candidatePrice = calculateSlotPrice(starsNum, i);
        
        // 🛡️ Gift/Premium pending orderlar bilan conflict tekshirish
        if (conflictPrices.has(candidatePrice)) {
          console.log(`⚠️ Slot ${i} skip: ${candidatePrice} so'm Gift/Premium bilan conflict`);
          continue; // Bu slotni o'tkazib yuborish
        }
        
        // Bo'sh va conflict yo'q slot topildi
        priceSlotIndex = i;
        amount = candidatePrice;
        break;
      }
      
      if (priceSlotIndex === -1) {
        // Barcha 20 ta slot band yoki conflict - BATAFSIL LOG
        const slots = priceSlots[String(starsNum)] || {};
        const slotDetails = Object.entries(slots).map(([idx, s]) => {
          const elapsed = Math.round((Date.now() - s.createdAt) / 1000);
          return `Slot${idx}:[id=${s.orderId},${elapsed}s]`;
        }).join(', ');
        console.log(`⚠️ SLOTS_FULL: stars=${starsNum}, band=${Object.keys(slots).length}/${PRICE_SLOT_CONFIG.MAX_SLOTS}`);
        console.log(`📊 Slot details: ${slotDetails || 'none'}`);
        console.log(`📊 Conflict prices: ${[...conflictPrices].join(', ')}`);
        return res.status(503).json({
          error: "Hozirda juda ko'p buyurtmalar mavjud. Iltimos, 1-2 daqiqadan keyin qayta urinib ko'ring.",
          code: "SLOTS_FULL"
        });
      }

      console.log(`🎯 Slot ${priceSlotIndex}: ${starsNum} stars = ${amount} so'm (max: ${starsNum * STARS_PRICE_PER_UNIT})`);
      
      // 🎯 MUHIM: Slotni DARHOL rezerv qilish (race condition oldini olish)
      // Order ID sifatida vaqtinchalik ID ishlatamiz
      const tempReservationId = `temp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      priceSlots[String(starsNum)][priceSlotIndex] = {
        orderId: tempReservationId,
        createdAt: Date.now()
      };
    }

    const cleanUsername = username.startsWith("@")
      ? username.slice(1)
      : username;
    
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1001)'); // Stars uchun alohida lock

      let finalAmount = amount;
      let finalDiscountAmount = 0;
      let promoCodeValid = null;

      // 🎁 PROMOCODE QO'LLASH (agar yuborilgan bo'lsa)
      if (applied_promocode) {
        const promoRes = await client.query(
          `SELECT * FROM promocodes WHERE code = $1 FOR UPDATE`,
          [applied_promocode]
        );
        if (promoRes.rows.length > 0) {
          const promo = promoRes.rows[0];
          // Validatsiya (type, amount, is_active, limits)
          if (promo.is_active && promo.used_count < promo.usage_limit) {
            if (promo.target_type === 'all' || promo.target_type === 'stars') {
              if (promo.target_amount === null || promo.target_amount === starsNum) {
                
                // Foydalanuvchi avval ushbu koddan foydalanganmi?
                const userUsage = await client.query(
                  `SELECT id FROM orders WHERE owner_user_id = $1 AND applied_promocode = $2 AND status IN ('success', 'pending', 'processing') LIMIT 1`,
                  [ownerUserId, applied_promocode]
                );

                if (userUsage.rows.length === 0) {
                  // Yaroqli! Apply discount
                  finalDiscountAmount = Math.floor(finalAmount * (promo.discount_percent / 100));
                  finalAmount = finalAmount - finalDiscountAmount;
                  promoCodeValid = promo.code;
                  
                  // Limitni oshirish
                  await client.query(
                    `UPDATE promocodes SET used_count = used_count + 1 WHERE id = $1`,
                    [promo.id]
                  );
                }
              }
            }
          }
        }
      }
      
      const uniqueSum = await generateUniqueOrderSum(finalAmount, client);

      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, applied_promocode, discount_amount, created_at)
         VALUES ($1, $2, $3, $4, 'stars', $5, $6, 'card', 'pending', 'pending', $7, $8, NOW())
         RETURNING *`,
        [orderId, ownerUserId, cleanUsername, recipient, starsNum, uniqueSum, promoCodeValid, finalDiscountAmount]
      );
      
      await client.query('COMMIT');
      order = result.rows[0];
      
      // 🎯 Slotni haqiqiy order ID bilan yangilash
      if (useDiscountSlot && discountPackage) {
        // Discount slot - faqat orderId ni yangilash
        if (discountPriceSlots[discountPackage.id] && discountPriceSlots[discountPackage.id][discountSlotIndex]) {
          discountPriceSlots[discountPackage.id][discountSlotIndex].orderId = order.id;
        }
      } else {
        // priceSlot ni haqiqiy orderId bilan yangilash
        if (priceSlots[String(starsNum)] && priceSlots[String(starsNum)][priceSlotIndex]) {
          priceSlots[String(starsNum)][priceSlotIndex].orderId = order.id;
        }
      }
      
      // 🔄 Global cache ga qo'shish
      addPriceToCache(order.summ, order.id, 'stars');
      
    } catch (err) {
      await client.query('ROLLBACK');
      
      // ❌ Xato bo'lsa, slotni bo'shatish
      if (useDiscountSlot && discountPackage) {
        if (discountPriceSlots[discountPackage.id] && discountPriceSlots[discountPackage.id][discountSlotIndex]) {
          delete discountPriceSlots[discountPackage.id][discountSlotIndex];
          console.log(`🔓 Xato tufayli discount slot bo'shatildi: Package ${discountPackage.id} Slot ${discountSlotIndex}`);
        }
      } else if (priceSlots[String(starsNum)] && priceSlots[String(starsNum)][priceSlotIndex]) {
        delete priceSlots[String(starsNum)][priceSlotIndex];
        console.log(`🔓 Xato tufayli slot bo'shatildi: Stars ${starsNum} Slot ${priceSlotIndex}`);
      }
      
      // Duplicate key xatosi bo'lsa, qayta urinish tavsiya qilinadi
      if (err.code === '23505') {
        console.log(`⚠️ Stars: Duplicate key xatosi: ${amount} so'm`);
        return res.status(503).json({
          error: "Narx to'qnashuvi. Iltimos, qayta urinib ko'ring.",
          code: "PRICE_COLLISION"
        });
      }
      
      throw err;
    } finally {
      client.release();
    }
    console.log(
      `🧾 Stars Order yaratildi: #${order.id} | ${cleanUsername} | ${order.summ} so'm | ${order.type_amount}⭐${useDiscountSlot ? ' (CHEGIRMA)' : ''}`
    );
    // BALANCE CHECKER GA SIGNAL
    try {
      fetch(`${INTERNAL_API_BASE}/api/balance/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }
    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status, order_type, type_amount, owner_user_id, expired_notified FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          
          // 🎯 Slotni bo'shatish (stars va discount)
          if (check.rows[0]?.order_type === 'stars') {
            releasePriceSlotByOrderId(order.id);
            releaseDiscountPriceSlotByOrderId(order.id);
          }
          
          // 🔄 Cache dan o'chirish
          removePriceFromCacheByOrderId(order.id);
          
          console.log(`⏰ Order #${order.id} expired`);
          
          // 📩 Foydalanuvchiga expired xabari yuborish
          const ownerUserId = check.rows[0]?.owner_user_id;
          const alreadyNotified = check.rows[0]?.expired_notified;
          if (ownerUserId && bot && !alreadyNotified) {
            try {
              const expiredNotificationText = `⚠️ Siz stars sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
              await bot.telegram.sendMessage(ownerUserId, expiredNotificationText);
              await pool.query(
                `UPDATE orders SET expired_notified = true WHERE id = $1`,
                [order.id]
              );
              console.log(`📩 Expired stars xabari yuborildi (setTimeout): user=${ownerUserId}, order=#${order.id}`);
            } catch (notifyErr) {
              console.error(`❌ Expired stars xabari yuborishda xato (user=${ownerUserId}):`, notifyErr.message);
            }
          }
        }
      } catch (e) {
        console.error("❌ Expiry tekshirishda xato:", e);
      }
    }, 5 * 60 * 1000);
    // Backward compatible response
    res.json({
      id: order.id,
      username: cleanUsername,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: order.status,
      created_at: order.created_at
    });
  } catch (err) {
    console.error("❌ /api/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 4️⃣ Order holatini olish (to'g'ri, xavfsiz versiya)
// ======================
app.get("/api/transactions/:id", telegramAuth, async (req, res) => {
  let { id } = req.params;
  // 🛑 ID yo‘q yoki raqam emas
  if (!id || isNaN(id)) {
    return res.status(400).json({ error: "ID noto‘g‘ri yoki kiritilmagan" });
  }
  id = Number(id); // integerga aylantiramiz
  try {
    const result = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ message: "Order not found" });
    }
    const order = result.rows[0];
    // Backward compatible status mapping
    let legacyStatus = order.status;
    if (order.status === 'processing') {
      // To'lov qabul qilindi, yuborilmoqda
      legacyStatus = 'payment_received';
    } else if (order.status === 'completed') {
      if (order.order_type === 'stars') legacyStatus = 'stars_sent';
      else if (order.order_type === 'premium') legacyStatus = 'premium_sent';
      else if (order.order_type === 'gift') legacyStatus = 'gift_sent';
    }
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: legacyStatus,
      payment_status: order.payment_status,
      created_at: order.created_at,
      order_type: order.order_type,
      transaction_id: order.transaction_id
    });
  } catch (err) {
    console.error("❌ /api/transactions/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 5️⃣ Telegram bot to‘lovni tasdiqlaydi — RobynHood versiyasi
// ======================
app.post("/api/payments/match", internalAuth, async (req, res) => {
  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || !amount)
      return res.status(400).json({ error: "card_last4 va amount kerak" });
    // 🔐 ATOMIC UPDATE - orders jadvalidan
    const updated = await pool.query(
      `UPDATE orders
       SET payment_status = 'paid',
           status = CASE WHEN status = 'pending' THEN 'processing' ELSE status END
       WHERE id = (
         SELECT id FROM orders 
         WHERE summ = $1 
           AND payment_status = 'pending'
           AND status = 'pending'
           AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '15 minutes'
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length)
      return res.status(404).json({ message: "Pending payment not found" });
    const order = updated.rows[0];
    console.log(`🎉 To'lov tasdiqlandi: #${order.id} | ${order.summ} so'm | ${order.order_type}`);
    // 🎁 Turga qarab delivery
    if (order.order_type === 'stars') {
      processReferralBonus(order.recipient_username, order.type_amount, order.id)
        .catch(err => console.error("❌ Referral bonus error:", err.message));
      sendStarsToUser(order)
        .then(tx => {
          console.log(`🌟 ${order.recipient_username} ga ${order.type_amount}⭐ yuborildi! TxID: ${tx}`);
        })
        .catch(err => {
          console.error("❌ Yulduz yuborishda xato:", err.message);
        });
    } else if (order.order_type === 'premium') {
      deliverPremiumOrder(order)
        .catch(err => console.error("❌ Premium delivery error:", err.message));
    } else if (order.order_type === 'gift') {
      sendGiftToUser(order)
        .catch(err => console.error("❌ Gift delivery error:", err.message));
    }
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: order.status,
      payment_status: order.payment_status,
      order_type: order.order_type
    });
  } catch (err) {
    console.error("❌ /api/payments/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ===============================
// 🔹 ADMIN — SEND STARS MANUALLY
// ===============================
app.post("/api/admin/stars/send/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });
    // Orderni topamiz (orders jadvalidan)
    const q = await pool.query(
      "SELECT * FROM orders WHERE id=$1",
      [id]
    );
    if (!q.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });
    const order = q.rows[0];
    if (order.status === "completed")
      return res.status(400).json({ error: "Yulduzlar allaqachon yuborilgan" });
    if (!order.recipient)
      return res.status(400).json({ error: "Recipient ID topilmadi" });
    // Yulduz yuborish funksiyasi
    const result = await sendStarsToUser(order);
    return res.json({
      success: true,
      message: "Stars yuborildi",
      result,
    });
  } catch (err) {
    console.error("❌ ADMIN SEND STARS ERROR:", err);
    return res.status(500).json({
      error: "Server xatosi",
      details: err.message,
    });
  }
});
// ======================
// 🔹 Yulduzlarni foydalanuvchiga yuborish - RobynHood API orqali --------------------------------REAL?TEST
// ======================
async function sendStarsToUser(order) {
  const { id: orderId, recipient: recipientId, type_amount: stars } = order;
  try {
    console.log("🔹 sendStarsToUser:", { orderId, recipientId, stars });
    const idempotencyKey = crypto.randomUUID();
    const purchaseBody = {
      product_type: "stars",
      recipient: recipientId,        
      quantity: String(stars),
      idempotency_key: idempotencyKey,
    };
    const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {  // real
    //const purchaseRes = await fetch("https://robynhood.parssms.info/api/test/purchase", { // test
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
      },
      body: JSON.stringify(purchaseBody),
    });
    const text = await purchaseRes.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new Error("Purchase API noto'g'ri format qaytardi: " + text);
    }
    console.log("📦 Purchase javob:", data);
    if (!data.transaction_id) {
      await pool.query(
        "UPDATE orders SET status = 'failed' WHERE id = $1",
        [orderId]
      );
      // 🎯 Slotni bo'shatish (stars va discount)
      releasePriceSlotByOrderId(orderId);
      releaseDiscountPriceSlotByOrderId(orderId);
      
      // 📢 Xato kanalga xabar
      sendUnifiedChannelNotification(order, 'stars', true).catch(err => console.error("Notif err:", err.message));
      
      throw new Error("Purchase error: " + JSON.stringify(data));
    }
    const txId = data.transaction_id;
    await pool.query(
      `UPDATE orders
       SET status='completed',
           transaction_id=$1
       WHERE id=$2`,
      [txId, orderId]
    );
    
    // 🎯 Slotni bo'shatish - order completed (stars va discount)
    releasePriceSlotByOrderId(orderId);
    releaseDiscountPriceSlotByOrderId(orderId);
    
    // 🔄 Cache dan o'chirish
    removePriceFromCacheByOrderId(orderId);
    
    console.log(`✅ Stars yuborildi: ${orderId} -> ${txId}`);
    // 📢 Kanalga xabar
    sendUnifiedChannelNotification(order, 'stars').catch(err => console.error("Notification error:", err));
    return txId;
  } catch (err) {
    console.error("❌ sendStarsToUser error:", err);
    await pool.query("UPDATE orders SET status='error' WHERE id=$1", [orderId]);
    // 🎯 Slotni bo'shatish - order error (stars va discount)
    releasePriceSlotByOrderId(orderId);
    releaseDiscountPriceSlotByOrderId(orderId);
    removePriceFromCacheByOrderId(orderId);
    
    // 📢 Xato kanalga xabar
    sendUnifiedChannelNotification(order, 'stars', true).catch(notifErr => console.error("Notif error:", notifErr));

    throw err;
  }
}
// ===============================
// 🎁 REFERRAL BONUS FUNCTION
// ===============================
async function processReferralBonus(username, stars, transactionId) {
  try {
    const clean = username.startsWith("@") ? username.slice(1) : username;
    // Foydalanuvchini topish va referrer user_id olish
    const userResult = await pool.query(
      "SELECT user_id, referrer_user_id FROM users WHERE username = $1",
      [clean]
    );
    if (userResult.rows.length === 0) {
      // User database-da yo'q, skip
      return;
    }
    const referrerUserId = userResult.rows[0].referrer_user_id;
    const userUserId = userResult.rows[0].user_id;
    if (!referrerUserId) {
      // Referrer yo'q, bonus yo'q
      return;
    }
    // Referrer ma'lumotlarini olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    if (referrerResult.rows.length === 0) {
      return;
    }
    const referrerUsername = referrerResult.rows[0].username;

    // Faqat 1 marta bonus berilishi tekshiruvi:
    const checkGiven = await pool.query(
      `SELECT id FROM referral_earnings WHERE referrer_username = $1 AND referee_username = $2 LIMIT 1`,
      [referrerUsername, clean]
    );
    if (checkGiven.rows.length > 0) return; // Oldin shu odamdan bonus olgan

    // Istalgan stars olinganda qat'iy 5 stars beriladi
    const bonusStars = 5;

    // Referrer balance-ga qo'shish (user_id orqali)
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, clean, bonusStars, transactionId]
    );
    // Referrals count update
    await pool.query(
      `UPDATE users 
       SET total_referrals = total_referrals + 1
       WHERE user_id = $1 AND total_earnings > 0`,
      [referrerUserId]
    );
    console.log(
      `🎁 REFERRAL BONUS: ${referrerUsername} (${referrerUserId}) ga ${bonusStars}⭐ bonus qo'shildi (${clean} tomonidan ${stars} star)`
    );
    // === INFLUENCER BONUS ===
    async function processInfluencerBonus(userId) {
      try {
        // Check if user already got influencer bonus
        const check = await pool.query(
          `SELECT influencer_bonus FROM users WHERE user_id = $1`, [userId]
        );
        if (check.rows[0] && check.rows[0].influencer_bonus) return; // already given
        // Check referrals count
        const user = await pool.query(
          `SELECT total_referrals, username FROM users WHERE user_id = $1`, [userId]
        );
        if (user.rows[0] && user.rows[0].total_referrals >= 10) {
          // Give bonus and mark as given
          await pool.query(
            `UPDATE users SET referral_balance = referral_balance + 15, influencer_bonus = true WHERE user_id = $1`, [userId]
          );
          await pool.query(
            `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
             VALUES ($1, $1, 15, NULL)`, [user.rows[0].username]
          );
          console.log(`🎉 Influencer bonus: ${user.rows[0].username} ga 15⭐ berildi`);
        }
      } catch (err) {
        console.error("❌ Influencer bonus error:", err.message);
      }
    }
    // Check influencer bonus
    await processInfluencerBonus(referrerUserId);
  } catch (err) {
    console.error("❌ processReferralBonus error:", err.message);
  }
}
// ======================
// 🎁 PREMIUM REFERRAL BONUS
// ======================
async function processPremiumReferralBonus(username, transactionId) {
  try {
    const clean = username.startsWith("@") ? username.slice(1) : username;
    const userResult = await pool.query(
      "SELECT user_id, referrer_user_id FROM users WHERE username = $1",
      [clean]
    );
    if (userResult.rows.length === 0) return;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    if (!referrerUserId) return;
    // Referrer ma'lumotlarini olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    if (referrerResult.rows.length === 0) return;
    const referrerUsername = referrerResult.rows[0].username;

    // Faqat 1 marta bonus berilishi tekshiruvi:
    const checkGiven = await pool.query(
      `SELECT id FROM referral_earnings WHERE referrer_username = $1 AND referee_username = $2 LIMIT 1`,
      [referrerUsername, clean]
    );
    if (checkGiven.rows.length > 0) return; // Oldin shu odamdan bonus olgan

    const bonusStars = 15;
    // Referrer balance-ga qo'shish (user_id orqali)
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, clean, bonusStars, transactionId]
    );
    console.log(
      `🎁 PREMIUM REFERRAL BONUS: ${referrerUsername} (${referrerUserId}) ga ${bonusStars}⭐ bonus qo'shildi (${clean} premium oldi)`
    );
  } catch (err) {
    console.error("❌ processPremiumReferralBonus error:", err.message);
  }
}
//-----------------------
// 🔍 PREMIUM SEARCH (FULL LOG VERSION)
//-----------------------
app.post("/api/premium/search", searchLimiter, telegramAuth, async (req, res) => {
  try {
    let { username } = req.body;
    console.log("\n================ PREMIUM SEARCH ================");
    console.log("📥 Keldi username:", username);
    if (!username) {
      console.log("⛔ username yo‘q");
      return res.status(400).json({ error: "username kerak" });
    }
    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;
    console.log("🧹 Tozalangan username:", clean);
    // RobynHood API
    console.log("🌐 Providerga so‘rov yuborilmoqda...");
    const response = await fetch("https://robynhood.parssms.info/api/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
        accept: "application/json",
      },
      body: JSON.stringify({
        product_type: "premium",
        query: clean,
        months: "3",
      }),
    });
    console.log("📡 Provider status:", response.status);
    const raw = await response.text();
    console.log("📦 Provider RAW response:", raw);
    // Provider offline -> "false"
    if (raw.trim() === "false") {
      console.log("❌ Provider OFFLINE yoki IP blok");
      return res.status(503).json({
        error: "Provider offline yoki IP bloklangan"
      });
    }
    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      console.log("❌ JSON parse xato:", err);
      return res.status(502).json({
        error: "Provider noto‘g‘ri format qaytardi",
        raw
      });
    }
    console.log("🔍 Provider JSON:", data);
    if (!data.ok || !data.found) {
      console.log("❌ found=false → Premium yo‘q yoki user topilmadi");
      return res.status(404).json({
        error: "❌ Premium mavjud emas yoki user yo‘q"
      });
    }
    const found = data.found;
    console.log("👤 found object:", found);
    // 🆔 Provider ID fieldlarini tekshiramiz
    const recipientId =
      found.id ||
      found.user_id ||
      found.uid ||
      found.recipient ||
      found.telegram_id ||
      null;
    console.log("🆔 Aniqlangan recipient ID:", recipientId);
    if (!recipientId) {
      console.log("❌ Provider ID qaytarmadi!");
      return res.status(404).json({
        error: "Provider ID qaytarmadi — premium sotib bo‘lmaydi"
      });
    }
    // 🖼 Rasm URL ajratish
    let imageUrl = null;
    if (found.photo) {
      const m = found.photo.match(/src="([^"]+)"/);
      imageUrl = m ? m[1] : null;
    }
    console.log("🖼 Image URL:", imageUrl);
    // Frontendga qaytariladigan JSON
    const responseJson = {
      username: clean,
      fullName: found.name || clean,
      imageUrl,
      recipient: recipientId
    };
    console.log("➡ Frontendga qaytmoqda:", responseJson);
    return res.json(responseJson);
  } catch (err) {
    console.error("💥 PREMIUM SEARCH SERVER ERROR:", err);
    return res.status(500).json({ error: "Server xato" });
  }
});
//-----------------------
// 🧾 PREMIUM ORDER YARATISH
//-----------------------
app.post("/api/premium", orderLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 🧾 PREMIUM ORDER YARATILMOQDA ===============");
    const { username, recipient, months, applied_promocode } = req.body;
    console.log("📥 Keldi:", req.body);

    const maxPendingOrders = 3;
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    if (tgUserId) {
        const activeOrdersRes = await pool.query(
          `SELECT COUNT(*) as count FROM orders WHERE owner_user_id = $1 AND status = 'pending' AND payment_status = 'pending'`,
          [tgUserId]
        );
        if (parseInt(activeOrdersRes.rows[0].count) >= maxPendingOrders) {
          return res.status(429).json({ error: "Sizda to'lanmagan buyurtmalar mavjud. Iltimos oldin ularni to'lang yoki biroz kuting." });
        }
    }

    if (!username || !recipient || !months) {
      console.log("❌ Parametrlar yetarli emas");
      return res.status(400).json({ error: "username, recipient, months kerak" });
    }
    const clean = username.startsWith("@") ? username.slice(1) : username;
    console.log("🧹 Tozalangan username:", clean);
    const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
    const baseAmount = priceMap[months];
    if (!baseAmount) {
      console.log("❌ months noto‘g‘ri:", months);
      return res.status(400).json({ error: "Noto‘g‘ri months" });
    }
    console.log("💰 Asosiy narx:", baseAmount);

    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;

    // 🎯 PREMIUM PRICE SLOT SYSTEM - Har bir premium davri uchun alohida 20 ta slot
    let priceSlotIndex = -1;
    let slotBasedPrice = 0;
    
    // Avval premiumPriceSlots ni bazadan sinxronlashtirish
    if (!premiumPriceSlots[months]) {
      premiumPriceSlots[months] = {};
    }
    
    // Bazadagi pending orderlarni tekshirish va slot tizimiga yuklash
    const pendingOrders = await pool.query(
      `SELECT id, summ, created_at FROM orders 
       WHERE order_type = 'premium' AND type_amount = $1 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'`,
      [months]
    );
    
    // Bazadagi pending orderlar uchun slotlarni band qilish
    for (const order of pendingOrders.rows) {
      const diff = baseAmount - order.summ;
      
      let slotIdx = -1;
      if (diff >= 0 && diff % 100 === 0 && diff / 100 < 10) {
        slotIdx = diff / 100;
      } else if (diff >= 50 && (diff - 50) % 100 === 0 && (diff - 50) / 100 < 10) {
        slotIdx = 10 + (diff - 50) / 100;
      }
      
      if (slotIdx >= 0 && slotIdx < 20 && !premiumPriceSlots[months][slotIdx]) {
        premiumPriceSlots[months][slotIdx] = {
          orderId: order.id,
          createdAt: new Date(order.created_at).getTime()
        };
      }
    }
    
    // Bo'sh slot topish
    for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
      if (premiumPriceSlots[months] && premiumPriceSlots[months][i]) {
        const elapsed = Date.now() - premiumPriceSlots[months][i].createdAt;
        if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) {
          continue;
        }
        // Expired slot - tozalash
        delete premiumPriceSlots[months][i];
      }
      
      // Bo'sh slot topildi
      priceSlotIndex = i;
      slotBasedPrice = calculatePremiumSlotPrice(months, i);
      break;
    }
    
    if (priceSlotIndex === -1) {
      // Barcha 20 ta slot band
      console.log(`⚠️ Barcha premium slotlar band: months=${months}, band slotlar: ${Object.keys(premiumPriceSlots[months] || {}).length}`);
      return res.status(503).json({
        error: "Hozirda juda ko'p buyurtmalar mavjud. Iltimos, 1-2 daqiqadan keyin qayta urinib ko'ring.",
        code: "SLOTS_FULL"
      });
    }

    console.log(`🎯 Premium Slot ${priceSlotIndex}: ${months} oy = ${slotBasedPrice} so'm (base: ${baseAmount})`);
    
    // 🎯 MUHIM: Slotni DARHOL rezerv qilish (race condition oldini olish)
    const tempReservationId = `temp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    if (!premiumPriceSlots[months]) {
      premiumPriceSlots[months] = {};
    }
    premiumPriceSlots[months][priceSlotIndex] = {
      orderId: tempReservationId,
      createdAt: Date.now()
    };

    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1002)');
      
      let finalAmount = slotBasedPrice;
      let finalDiscountAmount = 0;
      let promoCodeValid = null;

      // 🎁 PROMOCODE QO'LLASH
      // 🎁 PROMOCODE
      if (applied_promocode) {
        const promoRes = await client.query(
          `SELECT * FROM promocodes WHERE code = $1 FOR UPDATE`,
          [applied_promocode]
        );
        if (promoRes.rows.length > 0) {
          const promo = promoRes.rows[0];
          if (promo.is_active && promo.used_count < promo.usage_limit) {
            if (promo.target_type === 'all' || promo.target_type === 'premium') {
              if (promo.target_amount === null || promo.target_amount === months) {

                const userUsage = await client.query(
                  `SELECT id FROM orders WHERE owner_user_id = $1 AND applied_promocode = $2 AND status IN ('success', 'pending', 'processing') LIMIT 1`,
                  [ownerUserId, applied_promocode]
                );

                if (userUsage.rows.length === 0) {
                  finalDiscountAmount = Math.floor(finalAmount * (promo.discount_percent / 100));
                  finalAmount = finalAmount - finalDiscountAmount;
                  promoCodeValid = promo.code;
                  
                  await client.query(
                    `UPDATE promocodes SET used_count = used_count + 1 WHERE id = $1`,
                    [promo.id]
                  );
                }
              }
            }
          }
        }
      }

      const orderId = crypto.randomUUID();
      
      console.log("✅ Slot-based narx:", finalAmount);
      console.log("📝 Bazaga yozilmoqda...");

      const uniqueSum = await generateUniqueOrderSum(finalAmount, client);

      // 🟦 YANGI orders jadvaliga yozish
      const result = await client.query(
        `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, applied_promocode, discount_amount, created_at)
         VALUES ($1, $2, $3, $4, 'premium', $5, $6, 'card', 'pending', 'pending', $7, $8, NOW())
         RETURNING *`,
        [orderId, ownerUserId, clean, recipient, months, uniqueSum, promoCodeValid, finalDiscountAmount]
      );

      await client.query('COMMIT');
      order = result.rows[0];

      // 🎯 Slotni haqiqiy order ID bilan yangilash
      if (premiumPriceSlots[months] && premiumPriceSlots[months][priceSlotIndex]) {
        premiumPriceSlots[months][priceSlotIndex].orderId = order.id;
      }
      
      // 🔄 Global cache ga qo'shish
      addPriceToCache(order.summ, order.id, 'premium');
      
    } catch (err) {
      await client.query('ROLLBACK');
      
      // ❌ Xato bo'lsa, slotni bo'shatish
      if (premiumPriceSlots[months] && premiumPriceSlots[months][priceSlotIndex]) {
        delete premiumPriceSlots[months][priceSlotIndex];
        console.log(`🔓 Xato tufayli premium slot bo'shatildi: ${months} oy Slot ${priceSlotIndex}`);
      }
      
      // Duplicate key xatosi bo'lsa, qayta urinish tavsiya qilinadi
      if (err.code === '23505') {
        console.log(`⚠️ Premium: Duplicate key xatosi: ${slotBasedPrice} so'm`);
        return res.status(503).json({
          error: "Narx to'qnashuvi. Iltimos, qayta urinib ko'ring.",
          code: "PRICE_COLLISION"
        });
      }
      
      throw err;
    } finally {
      client.release();
    }
    console.log("🎉 ORDER CREATE →", order);
    //  BALANCE CHECKER GA SIGNAL - balansni yangilash
    try {
      fetch(`${INTERNAL_API_BASE}/api/balance/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'premium' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }
    // 8 daqiqadan keyin expired (frontend bilan sync)
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status, owner_user_id, expired_notified FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          
          // 🎯 Slotni bo'shatish
          releasePremiumPriceSlotByOrderId(order.id);
          
          // 🔄 Cache dan o'chirish
          removePriceFromCacheByOrderId(order.id);
          
          console.log(`⏰ Premium Order #${order.id} expired`);
          
          // 📩 Foydalanuvchiga expired xabari yuborish
          const ownerUserId = check.rows[0]?.owner_user_id;
          const alreadyNotified = check.rows[0]?.expired_notified;
          if (ownerUserId && bot && !alreadyNotified) {
            try {
              const expiredNotificationText = `⚠️ Siz premium sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
              await bot.telegram.sendMessage(ownerUserId, expiredNotificationText);
              await pool.query(
                `UPDATE orders SET expired_notified = true WHERE id = $1`,
                [order.id]
              );
              console.log(`📩 Expired premium xabari yuborildi (setTimeout): user=${ownerUserId}, order=#${order.id}`);
            } catch (notifyErr) {
              console.error(`❌ Expired premium xabari yuborishda xato (user=${ownerUserId}):`, notifyErr.message);
            }
          }
        }
      } catch (e) {
        console.error("❌ Premium Expiry tekshirishda xato:", e);
      }
    }, 5 * 60 * 1000);
    // Backward compatible response
    return res.json({ 
      success: true, 
      order: {
        id: order.id,
        username: clean,
        recipient: order.recipient,
        muddat_oy: order.type_amount,
        amount: order.summ,
        status: order.status,
        created_at: order.created_at
      }
    });
  } catch (err) {
    console.error("❌ PREMIUM ORDER ERROR:", err);
    return res.status(500).json({ error: "Server xato", details: err.message });
  }
});
//-----------------------
// 💳 PREMIUM PAYMENT MATCH
//-----------------------
app.post("/api/premium/match", internalAuth, async (req, res) => {
  try {
    console.log("\n=============== 💳 PREMIUM PAYMENT MATCH ===============");
    console.log("📥 Keldi:", req.body);
    const { amount, card_last4 } = req.body;
    if (!amount) {
      console.log("❌ Amount yo‘q");
      return res.status(400).json({ error: "amount kerak" });
    }
    console.log("🔎 Pending premium order qidirilmoqda:", amount);
    // 🔐 ATOMIC UPDATE - orders jadvalidan
    const updated = await pool.query(
      `UPDATE orders 
       SET payment_status='paid', status='processing'
       WHERE id=(
         SELECT id FROM orders 
         WHERE summ=$1 
           AND payment_status='pending' 
           AND status='pending'
           AND order_type='premium'
           AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '15 minutes'
         ORDER BY id DESC LIMIT 1 
         FOR UPDATE SKIP LOCKED
       ) 
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length) {
      console.log("❌ Pending premium TOPILMADI");
      return res.status(404).json({ error: "Pending premium topilmadi" });
    }
    const order = updated.rows[0];
    console.log("🎯 Topildi va processing:", order);
    
    // Premium yuborish
    deliverPremiumOrder(order)
      .then(result => {
        console.log("📦 deliverPremiumOrder javobi:", result);
        if (result.status === "completed") {
          processPremiumReferralBonus(order.recipient_username, order.id)
            .catch(err => console.error("❌ Premium referral bonus error:", err.message));
        }
      })
      .catch(err => console.error("❌ Premium delivery error:", err.message));
    
    return res.json({
      success: true,
      status: "processing",
      order_id: order.id
    });
  } catch (err) {
    console.error("❌ PREMIUM MATCH ERROR:", err);
    return res.status(500).json({ error: "Server xato", details: err.message });
  }
});
// ===============================
// 🔹 PREMIUMNI FOYDALANUVCHIGA YUBORISH-----------------------------------------------REAL? TEST
// ===============================  
async function sendPremiumToUser(orderId, recipientId, months) {
  try {
    console.log("\n=============== 🚀 PREMIUM YUBORILMOQDA ===============");
    console.log("📥 Parametrlar:", { orderId, recipientId, months });
    const check = await pool.query(
      "SELECT status FROM orders WHERE id=$1",
      [orderId]
    );
    console.log("🔎 Hozirgi status:", check.rows[0]);
    if (!check.rows.length)
      return { status: "error", reason: "order_not_found" };
    if (check.rows[0].status === "completed")
      return { status: "completed", reason: "already_sent" };
    const idempotencyKey = crypto.randomUUID();
    console.log("🧬 Idempotency Key:", idempotencyKey);
    const body = {
      product_type: "premium",
      recipient: recipientId,
      months: String(months),
      idempotency_key: idempotencyKey
    };
    console.log("🌐 Providerga so‘rov yuborilmoqda:", body);
    const resp = await fetch("https://robynhood.parssms.info/api/purchase", {   // real
    //const resp = await fetch("https://robynhood.parssms.info/api/test/purchase", {    //test
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
        accept: "application/json",
      },
      body: JSON.stringify(body)
    });
    const text = await resp.text();
    console.log("📦 Provider RAW:", text);
    let data;
    try { data = JSON.parse(text); }
    catch {
      console.log("❌ JSON parse xato!");
      await pool.query(
        "UPDATE orders SET status='failed' WHERE id=$1",
        [orderId]
      );
      return { status: "failed", reason: "invalid_api_response" };
    }
    console.log("📡 Provider JSON:", data);
    if (data.transaction_id) {
      console.log("✅ Premium success, bazaga yozilmoqda...");
      await pool.query(
        "UPDATE orders SET status='completed', transaction_id=$1 WHERE id=$2",
        [data.transaction_id, orderId]
      );
      
      // 🎯 Slotni bo'shatish
      releasePremiumPriceSlotByOrderId(orderId);
      
      // � Cache dan o'chirish
      removePriceFromCacheByOrderId(orderId);
      
      // �📢 Kanalga xabar
      sendChannelNotification(orderId, 'premium').catch(err => console.error("Notification error:", err));
      return { status: "completed", transaction_id: data.transaction_id };
    }
    console.log("❌ Provider error:", data.error);
    await pool.query(
      "UPDATE orders SET status='failed' WHERE id=$1",
      [orderId]
    );
    
    // 🎯 Slotni bo'shatish
    releasePremiumPriceSlotByOrderId(orderId);
    
    return { status: "failed", reason: data.error || "unknown" };
  } catch (err) {
    console.log("💥 PREMIUM SEND ERROR:", err);
    await pool.query(
      "UPDATE orders SET status='error' WHERE id=$1",
      [orderId]
    );
    
    // 🎯 Slotni bo'shatish
    releasePremiumPriceSlotByOrderId(orderId);
    
    return { status: "error", reason: err.message };
  }
}
//-----------------------
// 🔍 PREMIUM TRANSACTION HOLATI
//-----------------------
app.get("/api/premium/transactions/:id", telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 🔍 PREMIUM STATUS CHECK ===============");
    const id = Number(req.params.id);
    console.log("📥 ID:", id);
    const result = await pool.query(
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
      [id]
    );
    if (!result.rows.length) {
      console.log("❌ Order topilmadi");
      return res.status(404).json({ error: "Order topilmadi" });
    }
    const order = result.rows[0];
    console.log("📦 Javob:", order);
    // Backward compatible status mapping
    const legacyStatus = order.status === 'completed' ? 'premium_sent' : order.status;
    // Backward compatible response
    return res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      muddat_oy: order.type_amount,
      amount: order.summ,
      status: legacyStatus,
      payment_status: order.payment_status,
      transaction_id: order.transaction_id,
      created_at: order.created_at
    });
  } catch (err) {
    console.log("❌ STATUS ERROR:", err);
    return res.status(500).json({ error: "Server xato" });
  }
});
// ===============================
// 🔹 ADMIN — PREMIUM LIST   admin panel-------------------------------------------------------------------
// ===============================
app.get("/api/admin/premium/list", adminAuth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = `
      SELECT 
        o.id, o.order_id, o.owner_user_id, 
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.order_type,
        o.type_amount AS months,
        o.summ AS amount,
        o.payment_method, o.payment_status, o.status, o.transaction_id,
        o.created_at
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.order_type='premium'
    `;
    const params = [];
    // filter: status (premium_sent → completed mapping)
    if (status && status !== "all") {
      const dbStatus = status === 'premium_sent' ? 'completed' : status;
      params.push(dbStatus);
      query += ` AND o.status = $${params.length}`;
    }
    // filter: search (recipient_username, recipient)
    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (o.recipient_username ILIKE $${params.length - 1} OR o.recipient ILIKE $${params.length})`;
    }
    query += " ORDER BY o.id DESC";
    const result = await pool.query(query, params);
    
    // Status mapping: completed → premium_sent (frontend uchun)
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'premium_sent' : row.status
    }));
    
    res.json({ success: true, orders: mapped });
  } catch (err) {
    console.error("❌ /api/admin/premium/list ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ===============================
// 🔹 ADMIN — PREMIUM GET ONE
// ===============================
app.get("/api/admin/premium/get/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });
    const result = await pool.query(
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
      [id]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });
    res.json({ success: true, order: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/admin/premium/get ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ===============================
// 🔹 ADMIN — PREMIUM UPDATE (status)
// ===============================
app.patch("/api/admin/premium/update/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;
    if (!id || !status)
      return res.status(400).json({ error: "ID va status kerak" });
    const result = await pool.query(
      `UPDATE orders
       SET status=$1
       WHERE id=$2 AND order_type='premium'
       RETURNING *`,
      [status, id]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });

    if (['completed', 'delivered', 'failed', 'error', 'expired', 'cancelled', 'processing'].includes(status)) {
      releasePremiumPriceSlotByOrderId(result.rows[0].id);
      removePriceFromCacheByOrderId(result.rows[0].id);
    }
    
    res.json({ success: true, updated: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/admin/premium/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ===============================
// 🔹 ADMIN — RESEND PREMIUM
// ===============================
app.post("/api/admin/premium/resend/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });
    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
      [id]
    );
    if (!orderResult.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });
    const order = orderResult.rows[0];
    // Premium yuborish funksiyasini chaqiramiz
    const sendResult = await sendPremiumToUser(order.id, order.recipient_username, order.type_amount);
    res.json({ success: true, ...sendResult });
  } catch (err) {
    console.error("❌ /api/admin/premium/resend ERROR:", err);
    return res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 👑 ADMIN — MANUAL PREMIUM ORDER (Akkauntga kirib qo'lda yuborish uchun)
// ===============================
app.post("/api/admin/premium/manual", adminAuth, async (req, res) => {
  try {
    const { recipient_username, plan } = req.body;
    
    if (!recipient_username || !plan) {
      return res.status(400).json({ error: "recipient_username va plan kerak" });
    }
    
    if (!["1_oy", "1_yil"].includes(plan)) {
      return res.status(400).json({ error: "Plan faqat '1_oy' yoki '1_yil' bo'lishi kerak" });
    }
    
    // Plan ga qarab summa va type_amount
    const summ = plan === "1_oy" ? 57000 : 320000;
    const type_amount = plan === "1_oy" ? 1 : 12; // Baza integer qabul qiladi
    const months = plan === "1_oy" ? 1 : 12;
    
    // Username ni tozalash
    const cleanUsername = recipient_username.replace(/^@/, '').trim();
    
    if (!cleanUsername) {
      return res.status(400).json({ error: "Username bo'sh bo'lishi mumkin emas" });
    }
    
    const orderId = crypto.randomUUID();
    
    // Order yaratish - darhol delivered statusda
    const result = await pool.query(
      `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, created_at)
       VALUES ($1, $2, $3, $4, 'premium', $5, $6, 'admin_manual', 'completed', 'delivered', NOW())
       RETURNING *`,
      [orderId, null, cleanUsername, cleanUsername, type_amount, summ]
    );
    
    const order = result.rows[0];
    console.log(`👑 Manual Premium Order yaratildi: #${order.id} → @${cleanUsername} (${plan})`);

    sendManualPremiumSoldChannelMessage(order, plan, req.adminUser).catch((e) =>
      console.error('❌ Manual premium kanal xabari:', e.message)
    );

    res.json({ success: true, order });
  } catch (err) {
    console.error("❌ /api/admin/premium/manual ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 👤 ADMIN — GET ALL USERS
// ===============================
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/admin/users ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ===============================
// �🔐 SECRET INFORMATIONS — GET-------------------------------------------------------------------
// ===============================
app.get("/api/admin/secret", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM secret_informations");
    if (result.rows.length === 0) {
      const insert = await pool.query(`
        INSERT INTO secret_informations 
        (card_number, card_name, fragment_api, telegram_session, tg_api_id, tg_api_hash, bot_token)
        VALUES ('', '', '', '', '', '', '')
        RETURNING *;
      `);
      return res.json({ success: true, data: insert.rows[0] });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/admin/secret ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ===============================
// 🔐 SECRET INFORMATIONS — UPDATE
// ===============================
app.patch("/api/admin/secret/update", adminAuth, async (req, res) => {
  try {
    const {
      card_number,
      card_name,
      fragment_api,
      telegram_session,
      tg_api_id,
      tg_api_hash,
      bot_token
    } = req.body;
    const result = await pool.query(
      `
      UPDATE secret_informations
      SET 
        card_number = $1,
        card_name = $2,
        fragment_api = $3,
        telegram_session = $4,
        tg_api_id = $5,
        tg_api_hash = $6,
        bot_token = $7
      RETURNING *;
      `,
      [
        card_number,
        card_name,
        fragment_api,
        telegram_session,
        tg_api_id,
        tg_api_hash,
        bot_token
      ]
    );
    res.json({ success: true, updated: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/admin/secret/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ======================
//      callback
// ======================
app.post("/api/interview/callback", (req, res) => {
  console.log("2-qism:", req.body);
  res.json({ received: true });
});

// ===============================
// 🚀 DASHBOARD COMBINED API — Barcha ma'lumotlarni bitta so'rovda
// ===============================
app.get("/api/dashboard/init", telegramAuth, async (req, res) => {
  try {
    const { username, user_id } = req.query;
    const startTime = Date.now();
    
    const clean = username?.startsWith("@") ? username.slice(1) : username;
    
    // 🚀 Cached leaderboards (30 sekund cache)
    let leaderboardTop10 = getCachedLeaderboard();
    let referralTop10 = getCachedReferralLeaderboard();
    
    // Agar cache yo'q bo'lsa, bazadan olish
    const leaderboardPromise = leaderboardTop10 ? Promise.resolve({ rows: leaderboardTop10 }) : pool.query(`
      WITH order_totals AS (
        SELECT owner_user_id, SUM(COALESCE(summ, 0))::BIGINT AS total
        FROM orders
        WHERE status IN ('completed', 'delivered', 'stars_sent', 'premium_sent', 'gift_sent')
          AND order_type IN ('stars', 'premium', 'gift')
          AND owner_user_id IS NOT NULL
        GROUP BY owner_user_id
        HAVING SUM(COALESCE(summ, 0)) > 0
      ),
      ranked AS (
        SELECT ot.owner_user_id, COALESCE(u.name, u.username, 'Foydalanuvchi') AS nickname,
               ot.total, RANK() OVER (ORDER BY ot.total DESC) AS rank
        FROM order_totals ot
        LEFT JOIN users u ON u.user_id = ot.owner_user_id
      )
      SELECT * FROM ranked ORDER BY rank LIMIT 100
    `);
    
    const referralLeaderboardPromise = referralTop10 ? Promise.resolve({ rows: referralTop10 }) : pool.query(`
      WITH referral_counts AS (
        SELECT u2.user_id, COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
               COUNT(*) as referrals
        FROM users u1
        JOIN users u2 ON u1.referrer_user_id = u2.user_id
        WHERE u1.referrer_user_id IS NOT NULL AND u1.subscribe_user = true
        GROUP BY u2.user_id, u2.username, u2.name
      )
      SELECT *, ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
      FROM referral_counts
      ORDER BY referrals DESC LIMIT 10
    `);
    
    // Barcha so'rovlarni parallel bajarish
    const [
      leaderboardResult,
      referralLeaderboardResult,
      historyResult,
      referralStatsResult,
      unreadResult,
      myRankResult,
      myRefRankResult
    ] = await Promise.all([
      leaderboardPromise,
      referralLeaderboardPromise,
      
      // 3. User history (agar user_id mavjud bo'lsa)
      user_id ? pool.query(`
        SELECT id, recipient_username AS username, type_amount AS stars, summ AS amount,
          CASE 
            WHEN status = 'completed' AND order_type = 'stars' THEN 'stars_sent'
            WHEN status = 'completed' AND order_type = 'premium' THEN 'premium_sent'
            WHEN status = 'completed' AND order_type = 'gift' THEN 'gift_sent'
            ELSE status
          END AS status,
          created_at, order_type AS kind
        FROM orders WHERE owner_user_id = $1
        ORDER BY created_at DESC LIMIT 50
      `, [user_id]) : Promise.resolve({ rows: [] }),
      
      // 4. Referral stats (agar user_id mavjud bo'lsa)
      user_id ? pool.query(`
        SELECT referral_balance, total_earnings,
          (SELECT COUNT(*) FROM users WHERE referrer_user_id = $1) as total_referrals
        FROM users WHERE user_id = $1
      `, [user_id]) : Promise.resolve({ rows: [] }),
      
      // 5. Unread notifications count
      user_id ? pool.query(`
        SELECT COUNT(*) as unread_count 
        FROM notifications 
        WHERE (user_id = $1 OR is_global = true) AND is_read = false
      `, [user_id]) : Promise.resolve({ rows: [{ unread_count: 0 }] }),
      
      // 6. My leaderboard rank (parallel)
      user_id ? pool.query(`
        WITH order_totals AS (
          SELECT owner_user_id, SUM(COALESCE(summ, 0))::BIGINT AS total
          FROM orders
          WHERE status IN ('completed', 'delivered', 'stars_sent', 'premium_sent', 'gift_sent')
            AND order_type IN ('stars', 'premium', 'gift')
            AND owner_user_id IS NOT NULL
          GROUP BY owner_user_id
        ),
        ranked AS (
          SELECT ot.owner_user_id, COALESCE(u.name, u.username, 'Foydalanuvchi') AS nickname,
                 ot.total, RANK() OVER (ORDER BY ot.total DESC) AS rank
          FROM order_totals ot
          LEFT JOIN users u ON u.user_id = ot.owner_user_id
        )
        SELECT * FROM ranked WHERE owner_user_id = $1
      `, [user_id]) : Promise.resolve({ rows: [] }),
      
      // 7. My referral rank (parallel)
      user_id ? pool.query(`
        WITH referral_counts AS (
          SELECT u2.user_id, COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
                 COUNT(*) as referrals
          FROM users u1
          JOIN users u2 ON u1.referrer_user_id = u2.user_id
          WHERE u1.referrer_user_id IS NOT NULL AND u1.subscribe_user = true
          GROUP BY u2.user_id, u2.username, u2.name
        )
        SELECT *, ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
        FROM referral_counts WHERE user_id = $1
      `, [user_id]) : Promise.resolve({ rows: [] })
    ]);
    
    // Cache'ni yangilash (agar yangidan olingan bo'lsa)
    if (!leaderboardTop10) {
      setCachedLeaderboard(leaderboardResult.rows);
    }
    if (!referralTop10) {
      setCachedReferralLeaderboard(referralLeaderboardResult.rows);
    }
    
    const duration = Date.now() - startTime;
    console.log(`🚀 Dashboard init: ${duration}ms (cached: ${leaderboardTop10 ? 'yes' : 'no'})`);

    const salesTop10 = filterSalesLeaderboardTop10(leaderboardResult.rows);

    res.json({
      leaderboard: {
        top10: salesTop10,
        me: myRankResult.rows[0] || null
      },
      referralLeaderboard: {
        top10: referralLeaderboardResult.rows,
        me: myRefRankResult.rows[0] || null
      },
      history: historyResult.rows,
      referralStats: referralStatsResult.rows[0] || { referral_balance: 0, total_referrals: 0 },
      unreadCount: parseInt(unreadResult.rows[0]?.unread_count || 0),
      loadTime: duration
    });
    
  } catch (err) {
    console.error("❌ DASHBOARD INIT ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ===============================
// 📊 LEADERBOARD STATISTICS
// ===============================
app.get("/api/stats/leaderboard", telegramAuth, async (req, res) => {
  try {
    const { username, period } = req.query;
    
    const clean = username && username.startsWith("@")
      ? username.slice(1)
      : username;

    // Get user_id from username for "me" lookup
    let myUserId = null;
    if (clean) {
      const userRes = await pool.query("SELECT user_id FROM users WHERE username = $1", [clean]);
      if (userRes.rows.length > 0) {
        myUserId = userRes.rows[0].user_id;
      }
    }

    // Period filter: daily (bugun), weekly (7 kun orqaga), monthly (30 kun orqaga)
    let dateFilter = "";
    if (period === "daily") {
      // Bugun: 00:00:00 dan 23:59:59 gacha
      dateFilter = "AND o.created_at >= CURRENT_DATE AND o.created_at < CURRENT_DATE + INTERVAL '1 day'";
    } else if (period === "weekly") {
      // Bugundan 7 kun orqaga
      dateFilter = "AND o.created_at >= CURRENT_DATE - INTERVAL '6 days'";
    } else if (period === "monthly") {
      // Bugundan 30 kun orqaga
      dateFilter = "AND o.created_at >= CURRENT_DATE - INTERVAL '29 days'";
    }

    // Debug: Check if data exists
    const debugQuery = `
      SELECT 
        order_type, 
        status, 
        COUNT(*) as cnt,
        SUM(COALESCE(summ, 0))::BIGINT as total_sum
      FROM orders 
      WHERE status IN ('completed', 'delivered', 'stars_sent', 'premium_sent', 'gift_sent')
        AND order_type IN ('stars', 'premium', 'gift')
      GROUP BY order_type, status
    `;
    const debugResult = await pool.query(debugQuery);
    console.log("📊 DEBUG leaderboard orders:", debugResult.rows);

    const query = `
      WITH order_totals AS (
        SELECT 
          o.owner_user_id,
          SUM(COALESCE(o.summ, 0))::BIGINT AS total
        FROM orders o
        WHERE o.status IN ('completed', 'delivered', 'stars_sent', 'premium_sent', 'gift_sent')
          AND o.order_type IN ('stars', 'premium', 'gift')
          AND o.owner_user_id IS NOT NULL
          ${dateFilter}
        GROUP BY o.owner_user_id
        HAVING SUM(COALESCE(o.summ, 0)) > 0
      ),
      ranked AS (
        SELECT
          ot.owner_user_id,
          COALESCE(u.name, u.username, 'Foydalanuvchi') AS nickname,
          ot.total,
          RANK() OVER (ORDER BY ot.total DESC) AS rank
        FROM order_totals ot
        LEFT JOIN users u ON u.user_id = ot.owner_user_id
      )
      SELECT owner_user_id, nickname, total, rank FROM ranked
      ORDER BY rank
      LIMIT 100;
    `;
    console.log("📊 Leaderboard query (period:", period, "):", dateFilter);
    const result = await pool.query(query);
    const rows = result.rows;
    console.log("📊 Leaderboard results count:", rows.length);
    const top10 = filterSalesLeaderboardTop10(rows);
    const me = myUserId
      ? rows.find((r) => String(r.owner_user_id) === String(myUserId)) || null
      : null;
    res.json({
      top10,
      me,
    });
  } catch (err) {
    console.error("❌ LEADERBOARD ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ===============================
// 👤 USER HISTORY
// ===============================
app.get("/api/user/history/:userId", telegramAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId)
      return res.status(400).json({ error: "userId kerak" });
    const query = `
      SELECT
        id,
        recipient_username AS username,
        type_amount AS stars,
        summ AS amount,
        CASE 
          WHEN status = 'completed' AND order_type = 'stars' THEN 'stars_sent'
          WHEN status = 'completed' AND order_type = 'premium' THEN 'premium_sent'
          WHEN status = 'completed' AND order_type = 'gift' THEN 'gift_sent'
          ELSE status
        END AS status,
        created_at,
        order_type AS kind
      FROM orders
      WHERE owner_user_id = $1
      ORDER BY created_at DESC;
    `;
    const result = await pool.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ USER HISTORY ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ===============================
// 🎁 REFERRAL SYSTEM ENDPOINTS
// ===============================
// 1️⃣ Referral code bilan user ro'yxatdan o'tish yoki kirish
app.post("/api/referral/register", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, referral_code, language } = req.body;
    // Telegram ma'lumotlarini olish
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    const tgName = tgUser?.first_name 
      ? `${tgUser.first_name}${tgUser.last_name ? ' ' + tgUser.last_name : ''}`
      : null;
    const tgUsername = tgUser?.username || (username?.startsWith("@") ? username.slice(1) : username) || `user_${tgUserId}`;
    if (!tgUserId) {
      return res.status(400).json({ error: "Telegram user_id kerak" });
    }
    // User mavjudligini tekshirish (user_id orqali)
    let user = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      // Yangi user
      let referrer_user_id = null;
      // Referral code mavjudligini tekshirish
      if (referral_code) {
        const referrer = await pool.query(
          "SELECT user_id FROM users WHERE referral_code = $1",
          [referral_code]
        );
        if (referrer.rows.length === 0) {
          return res.status(400).json({ error: "Referral code noto'g'ri" });
        }
        referrer_user_id = referrer.rows[0].user_id;
      }
      // Yangi referral code generate qilish
      const new_code = crypto.randomBytes(6).toString("hex");
      // Yangi user qo'shish
      const newUser = await pool.query(
        `INSERT INTO users (name, username, user_id, referral_code, referrer_user_id, language)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [tgName, tgUsername, tgUserId, new_code, null, language || 'uz']
      );
      console.log(
        `👤 Yangi user ro'yxatdan o'tdi: ${tgUsername} (name: ${tgName}, user_id: ${tgUserId}, referrer_user_id: ${referrer_user_id || "yo'q"}, language: ${language || 'uz'})`
      );
      
      // ⚠️ NOTE: referrer_user_id is NOT SET here! Will be set only after admin approval via referral_requests
      console.log(`ℹ️ Referrer user_id set bo'lmadi - admin approval-ni kutilmoqda (referral_requests via)`);
      
      // 📝 Agar referrer mavjud bo'lsa - AUTOMATICALLY referral_request yaratiш
      if (referrer_user_id) {
        try {
          const referrerResult = await pool.query(
            "SELECT username FROM users WHERE user_id = $1",
            [referrer_user_id]
          );
          
          if (referrerResult.rows.length > 0) {
            const referrerUsername = referrerResult.rows[0].username;
            const is_subscribed = false; // New user har doim subscribe bo'lmagan
            
            await pool.query(
              `INSERT INTO referral_requests 
               (owner_user_id, owner_username, referrer_user_id, referrer_username, subscribe_referrer) 
               VALUES ($1, $2, $3, $4, $5)`,
              [tgUserId, tgUsername, referrer_user_id, referrerUsername, is_subscribed]
            );
            
            console.log(`📝 Referral request AUTO-created: ${tgUsername} -> ${referrerUsername}`);
          }
        } catch (err) {
          console.error("❌ Auto-create referral request error:", err.message);
        }
      }
      
      // 🎉 Yangi foydalanuvchiga xush kelibsiz xabari yuborish
      sendWelcomeMessage(tgUserId, tgName || tgUsername).catch(err => {
        console.error("❌ Welcome message error:", err.message);
      });
      
      return res.json(newUser.rows[0]);
    }
    // User allaqachon mavjud — name va username ni yangilash (agar o'zgargan bo'lsa)
    const existingUser = user.rows[0];
    let needsUpdate = false;
    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;
    if (tgName && existingUser.name !== tgName) {
      updateFields.push(`name = $${paramIndex++}`);
      updateValues.push(tgName);
      needsUpdate = true;
    }
    if (tgUsername && existingUser.username !== tgUsername) {
      updateFields.push(`username = $${paramIndex++}`);
      updateValues.push(tgUsername);
      needsUpdate = true;
    }
    if (needsUpdate) {
      updateValues.push(tgUserId);
      await pool.query(
        `UPDATE users SET ${updateFields.join(', ')} WHERE user_id = $${paramIndex}`,
        updateValues
      );
      console.log(`🔄 ${tgUserId} ma'lumotlari yangilandi`);
      
      // Yangilangan ma'lumotlarni qaytarish
      user = await pool.query("SELECT * FROM users WHERE user_id = $1", [tgUserId]);
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ /api/referral/register ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔔 SUBSCRIBE CHECK - Kanalga obuna bo'lganda subscribe_user ni true qilish
// Bu vaqtda referral ham aktivlashadi (agar referrer_user_id mavjud bo'lsa)
app.post("/api/user/subscribe-check", authLimiter, telegramAuth, async (req, res) => {
  try {
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    if (!tgUserId) {
      return res.status(400).json({ error: "Telegram user_id kerak" });
    }
    // User mavjudligini tekshirish
    const user = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi. Avval ro'yxatdan o'ting." });
    }
    // Agar allaqachon subscribe bo'lgan bo'lsa
    if (user.rows[0].subscribe_user === true) {
      return res.json({ 
        success: true, 
        message: "Allaqachon obuna bo'lgansiz",
        subscribe_user: true 
      });
    }
    // subscribe_user ni true qilish
    await pool.query(
      "UPDATE users SET subscribe_user = true WHERE user_id = $1",
      [tgUserId]
    );
    
    // 📝 Agar bu user referral request'ga ega bo'lsa - subscribe_referrer ni true qilish
    try {
      await pool.query(
        "UPDATE referral_requests SET subscribe_referrer = true WHERE owner_user_id = $1 AND is_accepted = false AND rejected_at IS NULL",
        [tgUserId]
      );
      console.log(`✅ Referral request updated: ${tgUserId} kanalga obuna bo'ldi`);
    } catch (err) {
      console.error("⚠️ Update referral request subscribe status error:", err.message);
    }
    
    // Agar bu user referrer orqali kelgan bo'lsa - referral aktivlashdi
    const referrerUserId = user.rows[0].referrer_user_id;
    if (referrerUserId) {
      console.log(`🎉 REFERRAL AKTIVLASHDI: User ${tgUserId} kanalga obuna bo'ldi. Referrer: ${referrerUserId}`);
      
      try {
        // Referrer ma'lumotlarini olish
        const referrerResult = await pool.query(
          "SELECT username FROM users WHERE user_id = $1",
          [referrerUserId]
        );
        if (referrerResult.rows.length > 0) {
          const referrerUsername = referrerResult.rows[0].username;
          const userName = user.rows[0].username || tgUserId;
          
          // Referrer ni total_referrals ni oshirish (Bonus +2 berilmaydi)
          await pool.query(
            `UPDATE users 
             SET total_referrals = total_referrals + 1
             WHERE user_id = $1`,
            [referrerUserId]
          );
          
          console.log(`🎁 REFERRAL TASDIQLANDI: ${referrerUsername} (${referrerUserId}) ning referali (${userName}) kanalga obuna bo'ldi. (Bonus bekor qilingan)`);
        }
      } catch (bonusErr) {
        console.error("❌ Subscribe referral update error:", bonusErr.message);
      }
    } else {
      console.log(`📢 User ${tgUserId} kanalga obuna bo'ldi`);
    }
    
    res.json({ 
      success: true, 
      message: "Obuna tasdiqlandi!",
      subscribe_user: true 
    });
  } catch (err) {
    console.error("❌ /api/user/subscribe-check ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 👤 USER INFO - Foydalanuvchi ma'lumotlarini olish
app.get("/api/user/info/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) {
      return res.status(400).json({ error: "user_id kerak" });
    }
    const user = await pool.query(
      "SELECT id, name, username, user_id, referral_code, referrer_user_id, referral_balance, total_referrals, subscribe_user, language, created_at FROM users WHERE user_id = $1",
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ /api/user/info ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 2️⃣ Referral link (personal code bilan)
app.get("/api/referral/link/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    const user = await pool.query(
      "SELECT name, username, referral_code, referral_balance, total_referrals FROM users WHERE user_id = $1",
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    const userData = user.rows[0];
    
    // Telegram Mini App Link
    const referralLink = `https://t.me/StarsjoyBot/starsjoy?startapp=${userData.referral_code}`;
    res.json({
      name: userData.name,
      username: userData.username,
      referral_code: userData.referral_code,
      referral_link: referralLink,
      referral_balance: userData.referral_balance,
      total_referrals: userData.total_referrals,
    });
  } catch (err) {
    console.error("❌ /api/referral/link ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 3️⃣ Referral statistics
app.get("/api/referral/stats/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    // User ma'lumotlari
    const user = await pool.query(
      `SELECT
        name,
        username,
        referral_balance,
        total_earnings,
        subscribe_user
       FROM users WHERE user_id = $1`,
      [user_id]
    );
    // Real do'stlar soni - users jadvalidan referrer_user_id orqali
    const friendsCount = await pool.query(
      `SELECT COUNT(*) as count FROM users WHERE referrer_user_id = $1`,
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.json({
        name: null,
        username: null,
        referral_balance: 0,
        total_earnings: 0,
        subscribe_user: false,
        total_referrals: parseInt(friendsCount.rows[0]?.count || 0),
      });
    }
    res.json({
      ...user.rows[0],
      total_referrals: parseInt(friendsCount.rows[0]?.count || 0),
    });
  } catch (err) {
    console.error("❌ /api/referral/stats ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 4️⃣ Referral earnings (qaysi referrallardan qancha earned)
app.get("/api/referral/earnings/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    // Username ni user_id dan olish
    const userResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [user_id]
    );
    if (userResult.rows.length === 0) {
      return res.json({ earnings: [] });
    }
    const username = userResult.rows[0].username;
    const earnings = await pool.query(
      `SELECT 
        re.referee_username,
        u.name as referee_name,
        re.earned_stars,
        re.created_at
       FROM referral_earnings re
       LEFT JOIN users u ON re.referee_username = u.username
       WHERE re.referrer_username = $1
       ORDER BY re.created_at DESC`,
      [username]
    );
    res.json({ earnings: earnings.rows });
  } catch (err) {
    console.error("❌ /api/referral/earnings ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 5️⃣ Referral balance claim request (Adminga notification yuborish)
app.post("/api/referral/claim-request", authLimiter, telegramAuth, async (req, res) => {
  try {
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    const { amount } = req.body;
    if (!tgUserId || !amount)
      return res.status(400).json({ error: "user_id va amount kerak" });
    // Check user existence
    const user = await pool.query(
      "SELECT name, username, referral_balance FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    const balance = user.rows[0].referral_balance;
    const userName = user.rows[0].name || user.rows[0].username;
    if (balance < 50) {
      return res.status(400).json({
        error: "Yetarli balans yo'q (kamida 50 star kerak)",
        current_balance: balance,
      });
    }
    // Adminga telegram orqali xabar yuborish
    const ADMIN_IDS = (process.env.ADMIN_IDS || "7827901505").split(",");
    const BOT_TOKEN = process.env.BOT_TOKEN;
    const message = `🎁 <b>REFERRAL CLAIM REQUEST</b>\n\n` +
      `👤 User: ${userName} (@${user.rows[0].username})\n` +
      `🆔 User ID: ${tgUserId}\n` +
      `💰 Referral Balance: ${balance} ⭐\n` +
      `✅ Claim Amount: ${amount} ⭐\n\n` +
      `<i>Admin, iltimos userni hisobiga ${amount} star qo'shing!</i>`;
    if (BOT_TOKEN) {
      for (const adminId of ADMIN_IDS) {
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: adminId.trim(),
            text: message,
            parse_mode: "HTML"
          })
        });
      }
    }
    console.log(`📩 Claim request from ${tgUserId}: ${amount} stars`);
    res.json({
      success: true,
      message: "So'rov adminga yuborildi",
      amount: amount
    });
  } catch (err) {
    console.error("❌ /api/referral/claim-request ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 6️⃣ Admin: Manually adjust user referral balance
app.post("/api/admin/users/:username/balance", adminAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const { amount, action } = req.body;
    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;
    if (!amount || !action) {
      return res.status(400).json({ error: "amount va action kerak" });
    }
    const numAmount = parseInt(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: "Noto'g'ri miqdor" });
    }
    // Check if user exists
    const userCheck = await pool.query(
      "SELECT referral_balance FROM users WHERE username = $1",
      [cleanUsername]
    );
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }
    const currentBalance = userCheck.rows[0].referral_balance || 0;
    let newBalance;
    if (action === "add") {
      newBalance = currentBalance + numAmount;
    } else if (action === "subtract") {
      newBalance = Math.max(0, currentBalance - numAmount); // Don't go below 0
    } else {
      return res.status(400).json({ error: "action 'add' yoki 'subtract' bo'lishi kerak" });
    }
    // Update balance
    const result = await pool.query(
      `UPDATE users SET referral_balance = $1 WHERE username = $2 RETURNING username, referral_balance`,
      [newBalance, cleanUsername]
    );
    console.log(`💰 Admin: @${cleanUsername} balance ${action === 'add' ? '+' : '-'}${numAmount} ⭐ (${currentBalance} → ${newBalance})`);
    
    res.json({ 
      success: true, 
      user: result.rows[0],
      previousBalance: currentBalance,
      newBalance: newBalance,
      change: action === 'add' ? numAmount : -numAmount
    });
  } catch (err) {
    console.error("❌ Admin balance adjust ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 6.5️⃣ Admin: Manually adjust user som balance
app.post("/api/admin/users/:username/som-balance", adminAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const { amount, action } = req.body;
    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;
    if (!amount || !action) {
      return res.status(400).json({ error: "amount va action kerak" });
    }
    const numAmount = parseInt(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: "Noto'g'ri miqdor" });
    }
    const userCheck = await pool.query(
      "SELECT som_balance FROM users WHERE username = $1",
      [cleanUsername]
    );
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }
    const currentBalance = userCheck.rows[0].som_balance || 0;
    let newBalance;
    if (action === "add") {
      newBalance = currentBalance + numAmount;
    } else if (action === "subtract") {
      newBalance = Math.max(0, currentBalance - numAmount);
    } else {
      return res.status(400).json({ error: "action 'add' yoki 'subtract' bo'lishi kerak" });
    }
    const result = await pool.query(
      `UPDATE users SET som_balance = $1 WHERE username = $2 RETURNING username, som_balance`,
      [newBalance, cleanUsername]
    );
    console.log(`💰 Admin: @${cleanUsername} som_balance ${action === 'add' ? '+' : '-'}${numAmount} so'm (${currentBalance} → ${newBalance})`);
    res.json({
      success: true,
      user: result.rows[0],
      previousBalance: currentBalance,
      newBalance: newBalance,
      change: action === 'add' ? numAmount : -numAmount
    });
  } catch (err) {
    console.error("❌ Admin som balance adjust ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// 🏷️ DISCOUNT PACKAGES API
// ======================
// Get all active discount packages with slot-based pricing (public)
app.get("/api/discount-packages", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM discount_packages WHERE is_active = true ORDER BY stars ASC"
    );
    
    // Har bir paketga slot narxini qo'shish
    const packagesWithSlotPrice = result.rows.map(pkg => {
      const slotIndex = getAvailableDiscountPriceSlot(pkg.id);
      const basePrice = pkg.stars * STARS_PRICE_PER_UNIT; // ✅ Asl narx: stars * 240
      const discountedPrice = pkg.discounted_price; // API dan olgan chegirma narx
      
      if (slotIndex === -1) {
        return {
          ...pkg,
          current_price: discountedPrice,
          base_price: basePrice,
          slot_available: false
        };
      }
      
      const slotPrice = calculateDiscountSlotPrice(discountedPrice, slotIndex);
      const slotsInfo = getDiscountPriceSlotsInfo(pkg.id);
      
      return {
        ...pkg,
        current_price: slotPrice,
        base_price: basePrice,
        discount_amount: basePrice - slotPrice,
        slot_index: slotIndex,
        available_slots: slotsInfo.availableSlots || PRICE_SLOT_CONFIG.MAX_SLOTS,
        slot_available: true
      };
    });
    
    res.json(packagesWithSlotPrice);
  } catch (err) {
    console.error("❌ GET discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Get all discount packages (admin)
app.get("/api/admin/discount-packages", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM discount_packages ORDER BY stars ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET admin discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Create discount package (admin)
app.post("/api/admin/discount-packages", adminAuth, async (req, res) => {
  try {
    const { stars, discount_percent, discounted_price } = req.body;
    if (!stars || !discount_percent || !discounted_price) {
      return res.status(400).json({ error: "stars, discount_percent, discounted_price kerak" });
    }
    const result = await pool.query(
      `INSERT INTO discount_packages (stars, discount_percent, discounted_price) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [stars, discount_percent, discounted_price]
    );
    console.log(`🏷️ Admin: Yangi chegirma paketi qo'shildi - ${stars} stars, ${discount_percent}%, ${discounted_price} so'm`);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ POST discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Update discount package (admin)
app.patch("/api/admin/discount-packages/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { stars, discount_percent, discounted_price, is_active } = req.body;
    const result = await pool.query(
      `UPDATE discount_packages 
       SET stars = COALESCE($1, stars),
           discount_percent = COALESCE($2, discount_percent),
           discounted_price = COALESCE($3, discounted_price),
           is_active = COALESCE($4, is_active),
           updated_at = NOW() AT TIME ZONE 'Asia/Tashkent'
       WHERE id = $5
       RETURNING *`,
      [stars, discount_percent, discounted_price, is_active, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Paket topilmadi" });
    }
    console.log(`🏷️ Admin: Chegirma paketi yangilandi - ID: ${id}`);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ PATCH discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Delete discount package (admin)
app.delete("/api/admin/discount-packages/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "DELETE FROM discount_packages WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Paket topilmadi" });
    }
    console.log(`🏷️ Admin: Chegirma paketi o'chirildi - ID: ${id}`);
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) {
    console.error("❌ DELETE discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Validate discount package price (used during order creation)
app.post("/api/validate-discount-price", async (req, res) => {
  try {
    const { stars, amount } = req.body;
    if (!stars || !amount) {
      return res.status(400).json({ valid: false, error: "stars va amount kerak" });
    }
    // Check if this is a valid discount package
    const result = await pool.query(
      "SELECT * FROM discount_packages WHERE stars = $1 AND discounted_price = $2 AND is_active = true",
      [stars, amount]
    );
    if (result.rows.length > 0) {
      res.json({ valid: true, package: result.rows[0] });
    } else {
      res.json({ valid: false, error: "Noto'g'ri chegirma paketi" });
    }
  } catch (err) {
    console.error("❌ Validate discount price ERROR:", err);
    res.status(500).json({ valid: false, error: "Server xato" });
  }
});

// ======================
// ✅ REFERRAL REQUESTS - VERIFICATION SYSTEM
// ======================

// GET pending referral requests for admin
app.get("/api/admin/referral-requests", adminAuth, async (req, res) => {
  try {
    const { filter } = req.query; // pending, accepted, rejected, all
    let query = "SELECT * FROM referral_requests";
    
    if (filter === "pending") {
      query += " WHERE is_accepted = false AND rejected_at IS NULL";
    } else if (filter === "accepted") {
      query += " WHERE is_accepted = true";
    } else if (filter === "rejected") {
      query += " WHERE rejected_at IS NOT NULL";
    }
    
    query += " ORDER BY created_at DESC";
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET referral-requests ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// POST - Create referral request (when user claims a referrer)
app.post("/api/referral-requests", telegramAuth, async (req, res) => {
  try {
    const { referrer_username } = req.body;
    const owner_user_id = req.user.id;
    const owner_username = req.user.username;
    
    if (!referrer_username) {
      return res.status(400).json({ error: "Referrer username kerak" });
    }
    
    // Check if referrer exists
    const referrerResult = await pool.query(
      "SELECT user_id, username FROM users WHERE username = $1",
      [referrer_username]
    );
    
    if (referrerResult.rows.length === 0) {
      return res.status(404).json({ error: "Referrer topilmadi" });
    }
    
    const referrer = referrerResult.rows[0];
    
    // Get current user subscription status
    const ownerResult = await pool.query(
      "SELECT subscribe_user FROM users WHERE user_id = $1",
      [owner_user_id]
    );
    
    const is_subscribed = ownerResult.rows.length > 0 ? ownerResult.rows[0].subscribe_user : false;
    
    // Check if request already exists
    const existingRequest = await pool.query(
      "SELECT id FROM referral_requests WHERE owner_user_id = $1 AND is_accepted = false AND rejected_at IS NULL",
      [owner_user_id]
    );
    
    if (existingRequest.rows.length > 0) {
      return res.status(400).json({ error: "Allaqachon tasdiqlanish kutilmoqda" });
    }
    
    // Create new request with subscription status
    const insertResult = await pool.query(
      `INSERT INTO referral_requests 
       (owner_user_id, owner_username, referrer_user_id, referrer_username, subscribe_referrer) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING *`,
      [owner_user_id, owner_username, referrer.user_id, referrer.username, is_subscribed]
    );
    
    console.log(`📝 Referral request yaratiлди: ${owner_username} (${owner_user_id}) -> ${referrer.username}, Subscribe: ${is_subscribed}`);
    res.json({ success: true, request: insertResult.rows[0] });
  } catch (err) {
    console.error("❌ POST referral-requests ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// PATCH - Admin approve referral request
app.patch("/api/admin/referral-requests/:id/approve", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get the request details
    const request = await pool.query(
      "SELECT * FROM referral_requests WHERE id = $1",
      [id]
    );
    
    if (request.rows.length === 0) {
      return res.status(404).json({ error: "Request topilmadi" });
    }
    
    const req_data = request.rows[0];
    
    // Check if already processed
    if (req_data.is_accepted || req_data.rejected_at) {
      return res.status(400).json({ error: "Bu so'rov allaqachon qayta ishlangi" });
    }
    
    // Update request to accepted
    await pool.query(
      "UPDATE referral_requests SET is_accepted = true WHERE id = $1",
      [id]
    );
    
    // Update user's referrer_user_id
    await pool.query(
      "UPDATE users SET referrer_user_id = $1 WHERE user_id = $2",
      [req_data.referrer_user_id, req_data.owner_user_id]
    );
    
    // 🎁 Agar subscriblagan bo'lsa - referrer ga +2 bonus qo'shish
    if (req_data.subscribe_referrer) {
      const bonusStars = 2;
      await pool.query(
        `UPDATE users 
         SET referral_balance = referral_balance + $1,
             total_earnings = total_earnings + $1,
             total_referrals = total_referrals + 1
         WHERE user_id = $2`,
        [bonusStars, req_data.referrer_user_id]
      );
      
      // Referral earnings log
      await pool.query(
        `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
         VALUES ($1, $2, $3, $4)`,
        [req_data.referrer_username, req_data.owner_username, bonusStars, null]
      );
      
      console.log(`✅ Admin: Referral tasdiqlandi + BONUS - ${req_data.owner_username} -> ${req_data.referrer_username} (+${bonusStars}⭐)`);
    } else {
      console.log(`✅ Admin: Referral tasdiqlandi (NO BONUS - not subscribed) - ${req_data.owner_username} -> ${req_data.referrer_username}`);
    }
    
    res.json({ success: true, message: "Referral tasdiqlandi" });
  } catch (err) {
    console.error("❌ PATCH approve referral ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// PATCH - Admin reject referral request
app.patch("/api/admin/referral-requests/:id/reject", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    const request = await pool.query(
      "SELECT * FROM referral_requests WHERE id = $1",
      [id]
    );
    
    if (request.rows.length === 0) {
      return res.status(404).json({ error: "Request topilmadi" });
    }
    
    const req_data = request.rows[0];
    
    if (req_data.is_accepted || req_data.rejected_at) {
      return res.status(400).json({ error: "Bu so'rov allaqachon qayta ishlangi" });
    }
    
    // Update request to rejected
    await pool.query(
      "UPDATE referral_requests SET rejected_at = NOW() WHERE id = $1",
      [id]
    );
    
    console.log(`❌ Admin: Referral rad etildi - ${req_data.owner_username} <- ${req_data.referrer_username}. Sabab: ${reason || "Ko'rsatilmagan"}`);
    res.json({ success: true, message: "Referral rad etildi" });
  } catch (err) {
    console.error("❌ PATCH reject referral ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 📋 Get specific user info
app.get("/api/admin/user/:userId", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await pool.query(
      "SELECT id, username, user_id, name, referral_balance, total_referrals FROM users WHERE user_id = $1",
      [userId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ GET user info ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 👥 Get user's referrals list
app.get("/api/admin/user/:userId/referrals", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const referrals = await pool.query(
      "SELECT id, username, user_id, referral_balance, subscribe_user, created_at FROM users WHERE referrer_user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    res.json(referrals.rows);
  } catch (err) {
    console.error("❌ GET user referrals ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 🗑️ Remove referral relationship
app.post("/api/admin/user/:userId/remove-referrer", adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🗑️  REFERRAL O'CHIRISH JARAYONI - BACKEND`);
    console.log(`${'='.repeat(60)}`);
    console.log(`📋 O'chiriladigan user_id: ${userId}`);
    
    // Get the user info before deletion for logging
    const userBefore = await pool.query(
      "SELECT username, referrer_user_id, id FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userBefore.rows.length === 0) {
      console.log(`❌ Foydalanuvchi topilmadi (user_id: ${userId})`);
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }
    
    const userInfo = userBefore.rows[0];
    console.log(`👤 Foydalanuvchi: @${userInfo.username} (DB ID: ${userInfo.id})`);
    console.log(`📊 Hozirgi referrer_user_id: ${userInfo.referrer_user_id || "NULL"}`);
    
    // Clear referrer_user_id
    console.log(`⏳ STEP 1: UPDATE users SET referrer_user_id = NULL WHERE user_id = ${userId}`);
    const updateResult = await pool.query(
      "UPDATE users SET referrer_user_id = NULL WHERE user_id = $1",
      [userId]
    );
    console.log(`✅ STEP 1 NATIJASI: ${updateResult.rowCount} qator o'zgartirildi`);
    
    // Check referral_requests records
    const refReqs = await pool.query(
      "SELECT id, owner_user_id, owner_username FROM referral_requests WHERE owner_user_id = $1",
      [userId]
    );
    console.log(`📋 STEP 2: referral_requests jadvalida: ${refReqs.rows.length} ta yozuv topildi`);
    
    if (refReqs.rows.length > 0) {
      console.log(`🔍 O'chiriladigan referral_requests:`);
      refReqs.rows.forEach(req => {
        console.log(`   - ID: ${req.id}, owner: ${req.owner_username}`);
      });
      
      // Delete from referral_requests if exists
      console.log(`⏳ STEP 2: DELETE FROM referral_requests WHERE owner_user_id = ${userId}`);
      const deleteResult = await pool.query(
        "DELETE FROM referral_requests WHERE owner_user_id = $1",
        [userId]
      );
      console.log(`✅ STEP 2 NATIJASI: ${deleteResult.rowCount} ta yozuv o'chirildi`);
    } else {
      console.log(`⚠️  STEP 2: referral_requests da yozuv yo'q, o'chirilishga hech narsa yo'q`);
    }
    
    // Verify the change
    const userAfter = await pool.query(
      "SELECT referrer_user_id FROM users WHERE user_id = $1",
      [userId]
    );
    const newValue = userAfter.rows[0]?.referrer_user_id;
    console.log(`📊 VERIFIKATSIYA: Yangi referrer_user_id qiymati: ${newValue || "NULL"}`);
    
    console.log(`\n✅ REFERRAL O'CHIRISH MUVAFFAQIYATLI!`);
    console.log(`${'='.repeat(60)}\n`);
    
    res.json({ 
      success: true, 
      message: "Referral o'chirildi",
      details: {
        userId,
        username: userInfo.username,
        referrer_user_id_cleared: true,
        referral_requests_deleted: refReqs.rows.length
      }
    });
  } catch (err) {
    console.error(`❌ POST remove referral ERROR:`, err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 7️⃣ Original claim endpoint (Admin uchun)
app.post("/api/referral/claim", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { username } = req.body;
    if (!username)
      return res.status(400).json({ error: "username kerak" });
    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;
    // Check user existence
    const user = await pool.query(
      "SELECT referral_balance FROM users WHERE username = $1",
      [clean]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    const balance = user.rows[0].referral_balance;
    if (balance < 50) {
      return res.status(400).json({
        error: "Yetarli balans yo'q (kamida 50 star kerak)",
        current_balance: balance,
      });
    }
    // 50 star yechish
    const claimedAmount = Math.floor(balance / 50) * 50;
    const remaining = balance - claimedAmount;
    await pool.query(
      `UPDATE users 
       SET referral_balance = $1
       WHERE username = $2`,
      [remaining, clean]
    );
    console.log(
      `✅ ${clean} referral balansdan ${claimedAmount} star yechdi. Qolgan: ${remaining}`
    );
    res.json({
      success: true,
      claimed_amount: claimedAmount,
      remaining_balance: remaining,
    });
  } catch (err) {
    console.error("❌ /api/referral/claim ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// � REFERRAL WITHDRAW — Referral balansdan gift yechish
// ======================
app.post("/api/referral/withdraw", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { giftId } = req.body;
    
    // Telegram user info
    const tgUser = req.telegramUser;
    const userId = tgUser?.id ? String(tgUser.id) : null;
    const username = tgUser?.username;
    
    if (!userId || !username) {
      return res.status(400).json({ error: "Telegram user ma'lumotlari topilmadi" });
    }
    if (!giftId) {
      return res.status(400).json({ error: "giftId kerak" });
    }
    
    // Gift ID tekshirish (minimum 50 stars)
    const ALLOWED_GIFT_IDS_WITHDRAW = [
      "5170144170496491616", "5170314324215857265",
      "5170564780938756245", "6028601630662853006",
      "5922558454332916696", "5801108895304779062",
      "5800655655995968830", "5956217000635139069",
      "5935895822435615975", "5969796561943660080",
      "5168043875654172773",
      "5170690322832818290", "5170521118301225164",
    ];
    const GIFT_STARS_WITHDRAW = {
      "5170144170496491616": 50, "5170314324215857265": 50,
      "5170564780938756245": 50, "6028601630662853006": 50,
      "5922558454332916696": 50, "5801108895304779062": 50,
      "5800655655995968830": 50, "5956217000635139069": 50,
      "5935895822435615975": 50, "5969796561943660080": 50,
      "5168043875654172773": 100,
      "5170690322832818290": 100, "5170521118301225164": 100,
    };
    
    if (!ALLOWED_GIFT_IDS_WITHDRAW.includes(giftId)) {
      return res.status(400).json({ error: "Noto'g'ri gift ID" });
    }
    
    const giftStars = GIFT_STARS_WITHDRAW[giftId];
    if (!giftStars) {
      return res.status(400).json({ error: "Gift narxi topilmadi" });
    }
    
    // User balansini tekshirish
    const userRes = await pool.query(
      "SELECT referral_balance FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    
    const currentBalance = userRes.rows[0].referral_balance || 0;
    if (currentBalance < giftStars) {
      return res.status(400).json({ 
        error: "Yetarli balans yo'q", 
        required: giftStars,
        current: currentBalance 
      });
    }
    
    // Transaction boshlaymiz
    const client = await pool.connect();
    let order;
    try {
      await client.query('BEGIN');
      
      // Balansni kamaytirish
      await client.query(
        "UPDATE users SET referral_balance = referral_balance - $1 WHERE user_id = $2",
        [giftStars, userId]
      );
      
      // Order yaratish (to'lov allaqachon qabul qilingan - referral balansdan)
      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders
         (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, gift_id, gift_anonymous, gift_comment, created_at)
         VALUES ($1, $2, $3, $4, 'gift', $5, 0, 'referral', 'completed', 'pending', $6, false, 'Referral yechish', NOW())
         RETURNING *`,
        [
          orderId,
          userId,
          username,
          username,  // O'ziga yuboriladi
          giftStars,
          giftId,
        ]
      );
      
      await client.query('COMMIT');
      order = result.rows[0];
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    
    console.log(`🎁 Referral withdraw: #${order.id} | @${username} | ${giftStars}⭐ (gift: ${giftId})`);
    
    // Gift yuborish (userbot orqali)
    sendGiftToUser(order);
    
    // Yangi balansni olish
    const newBalanceRes = await pool.query(
      "SELECT referral_balance FROM users WHERE user_id = $1",
      [userId]
    );
    const newBalance = newBalanceRes.rows[0]?.referral_balance || 0;
    
    res.json({
      success: true,
      order_id: order.id,
      gift_id: giftId,
      stars: giftStars,
      new_balance: newBalance,
      message: "Gift yuborilmoqda..."
    });
    
  } catch (err) {
    console.error("❌ /api/referral/withdraw ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// �🆕 USER LANGUAGE ENDPOINT
// ======================
app.post("/api/user/language", telegramAuth, async (req, res) => {
  try {
    const { username, language } = req.body;
    if (!username || !language) {
      return res.status(400).json({ error: "username va language kerak" });
    }
    // Validate language
    const validLanguages = ['uz', 'en', 'ru'];
    if (!validLanguages.includes(language)) {
      return res.status(400).json({ error: "Notog'ri language" });
    }
    const clean = username.startsWith("@") ? username.slice(1) : username;
    // Update user language
    const result = await pool.query(
      `UPDATE users SET language = $1 WHERE username = $2 RETURNING *`,
      [language, clean]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    console.log(`🌐 ${clean} language o'zgartirildi: ${language}`);
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/user/language ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ===============================
// 📢 CHANNEL NOTIFICATION
// ===============================
async function sendChannelNotification(orderId, type) {
  try {
    const res = await pool.query(`SELECT * FROM orders WHERE id = $1`, [orderId]);
    const order = res.rows[0];
    if (!order) return;
    const channelId = -1003752422150; // Orders channel ID
    const botToken = process.env.BOT_TOKEN;
    
    if (!botToken) {
        console.error("❌ BOT_TOKEN topilmadi (.env)");
        return;
    }
    const date = new Date().toLocaleString("en-US", { timeZone: "Asia/Tashkent" });
    let message = "";
    if (type === 'stars') {
      message = `
#${order.id}
✨ STARS YUBORILDI
👤 Username: @${(order.recipient_username || '').replace('@', '')}
⭐ Yuborilgan: ${order.type_amount}
💰 To'lov summasi: ${order.summ} so'm
📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'premium') {
      message = `
💎 PREMIUM YUBORILDI
#${order.id}
👤 Username: @${(order.recipient_username || '').replace('@', '')}
🕒 Muddat: ${order.type_amount} oy
💰 To‘lov summasi: ${order.summ} so‘m
📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'gift') {
      const anonLabel = order.gift_anonymous ? ' (anonim)' : '';
      message = `
🎁 GIFT YUBORILDI
#${order.id}
👤 Yuboruvchi: @${(order.owner_user_id || '').toString().replace('@', '')}${anonLabel}
👤 Qabul qiluvchi: @${(order.recipient_username || '').replace('@', '')}
⭐ Gift: ${order.type_amount}⭐
💰 To'lov summasi: ${order.summ} so'm
${order.gift_comment ? `💬 Izoh: ${order.gift_comment}` : ''}
🕒 ${date}
`;
    }
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: channelId,
        text: message.trim()
      })
    });
    
    console.log(`📢 Kanalga xabar yuborildi: #${order.id} (${type})`);
  } catch (err) {
    console.error("❌ Channel notification error:", err);
  }
}
// ======================
// 🎁 GIFT — Ruxsat etilgan gift IDlar va narxlar
// ======================
const ALLOWED_GIFT_IDS = [
  "5170145012310081615", "5170233102089322756",
  "5170250947678437525", "5168103777563050263",
  "5170144170496491616", "5170314324215857265",
  "5170564780938756245", "6028601630662853006",
  "5922558454332916696", "5801108895304779062",
  "5800655655995968830", "5956217000635139069", 
  "5893356958802511476", "5935895822435615975",
  "5969796561943660080", "5168043875654172773",
  "5170690322832818290",
  "5170521118301225164",
];
const GIFT_PRICE_MAP = { 15: 4500, 25: 6000, 50: 12000, 100: 24000 };
const GIFT_STARS_MAP = {
  "5170145012310081615": 15, "5170233102089322756": 15,
  "5170250947678437525": 25, "5168103777563050263": 25,
  "5170144170496491616": 50, "5170314324215857265": 50,
  "5170564780938756245": 50, "6028601630662853006": 50,
  "5922558454332916696": 50, "5801108895304779062": 50,
  "5800655655995968830": 50, "5956217000635139069": 50, 
  "5893356958802511476": 50, "5935895822435615975": 50,
  "5969796561943660080": 50, "5168043875654172773": 100,
  "5170690322832818290": 100,
  "5170521118301225164": 100,
};
// ======================
// 🎁 GIFT ORDER — Order yaratish (to'lov kutish)
// ======================
app.post("/api/gift/order", orderLimiter, telegramAuth, async (req, res) => {
  try {
    const { recipientUsername, giftId, anonymous, comment } = req.body;

    const maxPendingOrders = 3;
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    if (tgUserId) {
        const activeOrdersRes = await pool.query(
          `SELECT COUNT(*) as count FROM orders WHERE owner_user_id = $1 AND status = 'pending' AND payment_status = 'pending'`,
          [tgUserId]
        );
        if (parseInt(activeOrdersRes.rows[0].count) >= maxPendingOrders) {
          return res.status(429).json({ error: "Sizda to'lanmagan buyurtmalar mavjud. Iltimos oldin ularni to'lang yoki biroz kuting." });
        }
    }

    if (!recipientUsername || !giftId) {
      return res.status(400).json({ error: "recipientUsername va giftId kerak" });
    }
    if (!ALLOWED_GIFT_IDS.includes(giftId)) {
      return res.status(400).json({ error: "Noto'g'ri gift ID" });
    }
    // Stars miqdorini server tekshiradi
    const serverStars = GIFT_STARS_MAP[giftId];
    if (!serverStars) {
      return res.status(400).json({ error: "Gift ID uchun narx topilmadi" });
    }
    const amount = GIFT_PRICE_MAP[serverStars];
    if (!amount) {
      return res.status(400).json({ error: "Gift narxi topilmadi" });
    }
    if (comment && comment.length > 128) {
      return res.status(400).json({ error: "Izoh 128 belgidan oshmasligi kerak" });
    }

    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;

    // 🎯 GIFT PRICE SLOT SYSTEM - Har bir gift stars miqdori uchun alohida 20 ta slot
    let priceSlotIndex = -1;
    let slotBasedPrice = 0;
    
    // Avval giftPriceSlots ni bazadan sinxronlashtirish
    if (!giftPriceSlots[serverStars]) {
      giftPriceSlots[serverStars] = {};
    }
    
    // Bazadagi pending orderlarni tekshirish va slot tizimiga yuklash
    const pendingOrders = await pool.query(
      `SELECT id, summ, created_at FROM orders 
       WHERE order_type = 'gift' AND type_amount = $1 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'`,
      [serverStars]
    );
    
    // Bazadagi pending orderlar uchun slotlarni band qilish
    for (const order of pendingOrders.rows) {
      const diff = amount - order.summ;
      
      let slotIdx = -1;
      if (diff >= 0 && diff % 100 === 0 && diff / 100 < 10) {
        slotIdx = diff / 100;
      } else if (diff >= 50 && (diff - 50) % 100 === 0 && (diff - 50) / 100 < 10) {
        slotIdx = 10 + (diff - 50) / 100;
      }
      
      if (slotIdx >= 0 && slotIdx < 20 && !giftPriceSlots[serverStars][slotIdx]) {
        giftPriceSlots[serverStars][slotIdx] = {
          orderId: order.id,
          createdAt: new Date(order.created_at).getTime()
        };
      }
    }
    
    // Bo'sh slot topish
    for (let i = 0; i < GIFT_SLOT_CONFIG.MAX_SLOTS; i++) {
      if (giftPriceSlots[serverStars] && giftPriceSlots[serverStars][i]) {
        const elapsed = Date.now() - giftPriceSlots[serverStars][i].createdAt;
        if (elapsed <= GIFT_SLOT_CONFIG.SLOT_TIMEOUT) {
          continue; // Slot hali band
        }
        // Expired slot - tozalash
        delete giftPriceSlots[serverStars][i];
      }
      
      // Bo'sh slot topildi
      priceSlotIndex = i;
      slotBasedPrice = calculateGiftSlotPrice(serverStars, i);
      break;
    }
    
    if (priceSlotIndex === -1) {
      // Barcha 20 ta slot band
      console.log(`⚠️ Barcha gift slotlar band: stars=${serverStars}, band slotlar: ${Object.keys(giftPriceSlots[serverStars] || {}).length}`);
      return res.status(503).json({
        error: "Hozirda juda ko'p buyurtmalar mavjud. Iltimos, 1-2 daqiqadan keyin qayta urinib ko'ring.",
        code: "SLOTS_FULL"
      });
    }

    console.log(`🎯 Gift Slot ${priceSlotIndex}: ${serverStars} stars = ${slotBasedPrice} so'm (base: ${amount})`);
    
    // 🎯 MUHIM: Slotni DARHOL rezerv qilish (race condition oldini olish)
    const tempReservationId = `temp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    if (!giftPriceSlots[serverStars]) {
      giftPriceSlots[serverStars] = {};
    }
    giftPriceSlots[serverStars][priceSlotIndex] = {
      orderId: tempReservationId,
      createdAt: Date.now()
    };

    const cleanUsername = recipientUsername.startsWith("@")
      ? recipientUsername.slice(1)
      : recipientUsername;

    // Order yaratish (orders jadvaliga yozamiz)
    const client = await pool.connect();
    let order;
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1003)'); // Gift uchun alohida lock
      
      let finalAmount = slotBasedPrice;
      let finalDiscountAmount = 0;
      let promoCodeValid = null;
      const { applied_promocode } = req.body;

      // 🎁 PROMOCODE QO'LLASH
      if (applied_promocode) {
        const promoRes = await client.query(
          `SELECT * FROM promocodes WHERE code = $1 FOR UPDATE`,
          [applied_promocode]
        );
        if (promoRes.rows.length > 0) {
          const promo = promoRes.rows[0];
          if (promo.is_active && promo.used_count < promo.usage_limit) {
            if (promo.target_type === 'all' || promo.target_type === 'gift') {
              if (promo.target_amount === null || promo.target_amount === serverStars) {
                
                const userUsage = await client.query(
                  `SELECT id FROM orders WHERE owner_user_id = $1 AND applied_promocode = $2 AND status IN ('success', 'pending', 'processing') LIMIT 1`,
                  [ownerUserId, applied_promocode]
                );

                if (userUsage.rows.length === 0) {
                  finalDiscountAmount = Math.floor(finalAmount * (promo.discount_percent / 100));
                  finalAmount = finalAmount - finalDiscountAmount;
                  promoCodeValid = promo.code;
                  
                  await client.query(
                    `UPDATE promocodes SET used_count = used_count + 1 WHERE id = $1`,
                    [promo.id]
                  );
                }
              }
            }
          }
        }
      }

const uniqueSum = await generateUniqueOrderSum(finalAmount, client);

      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders
         (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, gift_id, gift_anonymous, gift_comment, applied_promocode, discount_amount, created_at)
         VALUES ($1, $2, $3, $4, 'gift', $5, $6, 'card', 'pending', 'pending', $7, $8, $9, $10, $11, NOW())
         RETURNING *`,
        [
          orderId,
          ownerUserId,
          cleanUsername,
          cleanUsername,
          serverStars,
          uniqueSum,
          giftId,
          anonymous === true,
          comment && comment.trim() ? comment.trim() : null,
          promoCodeValid,
          finalDiscountAmount
        ]
      );
      await client.query('COMMIT');
      order = result.rows[0];

      // 🎯 Slotni haqiqiy order ID bilan yangilash
      if (giftPriceSlots[serverStars] && giftPriceSlots[serverStars][priceSlotIndex]) {
        giftPriceSlots[serverStars][priceSlotIndex].orderId = order.id;
      }

      // 🔄 Global cache ga qo'shish
      addPriceToCache(order.summ, order.id, 'gift');
      
      // 🔄 Global cache ga qo'shish
      addPriceToCache(order.summ, order.id, 'gift');
      
    } catch (err) {
      await client.query('ROLLBACK');
      
      // ❌ Xato bo'lsa, slotni bo'shatish
      if (giftPriceSlots[serverStars] && giftPriceSlots[serverStars][priceSlotIndex]) {
        delete giftPriceSlots[serverStars][priceSlotIndex];
        console.log(`🔓 Xato tufayli gift slot bo'shatildi: ${serverStars} stars Slot ${priceSlotIndex}`);
      }
      
      // Duplicate key xatosi bo'lsa, qayta urinish tavsiya qilinadi
      if (err.code === '23505') {
        console.log(`⚠️ Gift: Duplicate key xatosi: ${slotBasedPrice} so'm`);
        return res.status(503).json({
          error: "Narx to'qnashuvi. Iltimos, qayta urinib ko'ring.",
          code: "PRICE_COLLISION"
        });
      }
      
      throw err;
    } finally {
      client.release();
    }
    console.log(`🎁 Gift order yaratildi: #${order.id} | ${ownerUserId} → @${cleanUsername} | ${serverStars}⭐ | ${order.summ} so'm`);

    // BALANCE CHECKER GA SIGNAL
    try {
      fetch(`${INTERNAL_API_BASE}/api/balance/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }

    // 8 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status, owner_user_id, expired_notified FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          
          // 🎯 Slotni bo'shatish
          releaseGiftPriceSlotByOrderId(order.id);
          
          // 🔄 Cache dan o'chirish
          removePriceFromCacheByOrderId(order.id);
          
          console.log(`⏰ Gift Order #${order.id} expired`);
          
          // 📩 Foydalanuvchiga expired xabari yuborish
          const ownerUserId = check.rows[0]?.owner_user_id;
          const alreadyNotified = check.rows[0]?.expired_notified;
          if (ownerUserId && bot && !alreadyNotified) {
            try {
              const expiredNotificationText = `⚠️ Siz gift yuborishga harakat qildingiz, ammo to'lov amalga oshirilmadi.

Agar qandaydir muammo yuzaga kelgan bo'lsa, iltimos admin bilan bog'laning:

👉 @StarsjoySupport`;
              await bot.telegram.sendMessage(ownerUserId, expiredNotificationText);
              await pool.query(
                `UPDATE orders SET expired_notified = true WHERE id = $1`,
                [order.id]
              );
              console.log(`📩 Expired gift xabari yuborildi (setTimeout): user=${ownerUserId}, order=#${order.id}`);
            } catch (notifyErr) {
              console.error(`❌ Expired gift xabari yuborishda xato (user=${ownerUserId}):`, notifyErr.message);
            }
          }
        }
      } catch (e) {
        console.error("❌ Gift expiry xatosi:", e);
      }
    }, 5 * 60 * 1000);

    // username / recipient_username — oluvchi (stars/premium bilan bir xil ma'noda)
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: order.recipient_username,
      gift_id: order.gift_id,
      stars: order.type_amount,
      amount: order.summ,
      anonymous: order.gift_anonymous,
      comment: order.gift_comment,
      status: order.status,
      created_at: order.created_at
    });
  } catch (err) {
    console.error("❌ /api/gift/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 🎁 GIFT STATUS — Order holatini olish (orders jadvalidan)
// ======================
app.get("/api/gift/status/:id", telegramAuth, async (req, res) => {
  let { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ error: "ID noto'g'ri" });
  }
  id = Number(id);
  try {
    const result = await pool.query(
      "SELECT * FROM orders WHERE id = $1 AND order_type = 'gift'",
      [id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Gift order topilmadi" });
    }
    const order = result.rows[0];
    // Backward compatible status mapping
    const legacyStatus = order.status === 'completed' ? 'gift_sent' : order.status;
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: order.recipient_username,
      gift_id: order.gift_id,
      stars: order.type_amount,
      amount: order.summ,
      anonymous: order.gift_anonymous,
      comment: order.gift_comment,
      status: legacyStatus,
      created_at: order.created_at
    });
  } catch (err) {
    console.error("❌ /api/gift/status error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 🎁 GIFT MATCH — SMS to'lov tasdiqlash (orders jadvalidan)
// ======================
app.post("/api/gift/match", internalAuth, async (req, res) => {
  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || !amount) {
      return res.status(400).json({ error: "card_last4 va amount kerak" });
    }
    const updated = await pool.query(
      `UPDATE orders
       SET payment_status = 'paid',
           status = 'processing'
       WHERE id = (
         SELECT id FROM orders
         WHERE summ = $1 
           AND payment_status = 'pending' 
           AND status = 'pending'
           AND order_type = 'gift'
           AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '15 minutes'
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length) {
      return res.status(404).json({ message: "Pending gift payment not found" });
    }
    const order = updated.rows[0];
    console.log(`🎉 Gift to'lov tasdiqlandi: #${order.id} | oluvchi: @${order.recipient_username} | ${order.summ} so'm`);
    
    // Gift yuborish
    sendGiftToUser(order)
      .then(() => {
        console.log(`🎁 Gift yuborildi: #${order.id} → @${order.recipient}`);
      })
      .catch(err => {
        console.error(`❌ Gift yuborishda xato #${order.id}:`, err.message);
      });
    
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: order.recipient_username,
      gift_id: order.gift_id,
      amount: order.summ,
      status: order.status,
      payment_status: order.payment_status
    });
  } catch (err) {
    console.error("❌ /api/gift/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 🎁 GIFT SEND — Userbot (GramJS) orqali gift yuborish
// ======================
async function sendGiftToUser(order) {
  try {
    // recipient / recipient_username — qabul qiluvchi (username); yuboruvchi owner_user_id + users jadvali
    console.log(`🎁 sendGiftToUser: #${order.id} → @${order.recipient} | gift: ${order.gift_id}`);
    // balanceChecker.js dagi userbot orqali gift yuborish
    const giftRes = await fetch(`${BALANCE_CHECKER_URL}/api/gift/send-userbot`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': INTERNAL_SECRET,
      },
      body: JSON.stringify({
        recipientUsername: order.recipient, // TO'G'RILANDI: recipient (qabul qiluvchi)
        giftId: order.gift_id,
        message: order.gift_comment || undefined,
        anonymous: order.gift_anonymous || false,
      }),
    });
    const giftData = await giftRes.json();
    if (!giftData.success) {
      await pool.query(
        "UPDATE orders SET status = 'error' WHERE id = $1",
        [order.id]
      );
      releaseGiftPriceSlotByOrderId(order.id);
      
      // 📢 Xato kanalga xabar
      sendUnifiedChannelNotification(order, 'gift', true).catch(err => console.error("Notif err:", err.message));
      
      const err = new Error(giftData.error || "Gift yuborishda xato");
      err.notified = true;
      throw err;
    }
    // Muvaffaqiyatli — statusni yangilash
    await pool.query(
      "UPDATE orders SET status = 'completed' WHERE id = $1",
      [order.id]
    );
    releaseGiftPriceSlotByOrderId(order.id);
    
    // 🔄 Cache dan o'chirish
    removePriceFromCacheByOrderId(order.id);
    
    console.log(`✅ Gift muvaffaqiyatli yuborildi: #${order.id} → @${order.recipient}`);
    // 📢 Kanalga xabar
    sendUnifiedChannelNotification(order, 'gift').catch(err => console.error("Gift notification error:", err));
    return { status: 'delivered', message: 'Gift muvaffaqiyatli yuborildi' };
  } catch (err) {
    console.error(`❌ sendGiftToUser error #${order.id}:`, err);
    await pool.query(
      "UPDATE orders SET status = 'error' WHERE id = $1",
      [order.id]
    );
    releaseGiftPriceSlotByOrderId(order.id);
    removePriceFromCacheByOrderId(order.id); // 🧹 Cache don't stuck with errored pending slot
    
    // 📢 Xato kanalga xabar
    sendUnifiedChannelNotification(order, 'gift', true).catch(err => console.error("Notif err:", err.message));
    
    throw err;
  }
}
// ======================
// 🎁 ADMIN — Gift buyurtmalar ro'yxati
// ======================
app.get("/api/admin/gift/list", adminAuth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = `
      SELECT 
        o.id, o.order_id, o.owner_user_id, 
        u.username AS sender_username,
        o.recipient_username,
        o.recipient_username AS username,
        o.recipient,
        o.order_type,
        o.type_amount AS stars,
        o.summ AS amount,
        o.payment_method, o.payment_status, o.status, o.transaction_id,
        o.gift_id, o.gift_anonymous, o.gift_comment,
        o.created_at
      FROM orders o
      LEFT JOIN users u ON u.user_id = o.owner_user_id
      WHERE o.order_type='gift'
    `;
    const params = [];
    // filter: status (gift_sent → completed mapping)
    if (status && status !== "all") {
      const dbStatus = status === 'gift_sent' ? 'completed' : status;
      params.push(dbStatus);
      query += ` AND o.status = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (o.owner_user_id::text ILIKE $${params.length - 1} OR o.recipient_username ILIKE $${params.length})`;
    }
    query += " ORDER BY o.id DESC";
    const result = await pool.query(query, params);
    
    // Status mapping: completed → gift_sent (frontend uchun)
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'gift_sent' : row.status
    }));
    
    res.json({ success: true, orders: mapped });
  } catch (err) {
    console.error("❌ /api/admin/gift/list ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ======================
// 🎁 ADMIN — Gift status o'zgartirish
// ======================
app.patch("/api/admin/gift/update/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;
    if (!id || !status)
      return res.status(400).json({ error: "ID va status kerak" });
    const result = await pool.query(
      `UPDATE orders
       SET status=$1
       WHERE id=$2 AND order_type='gift'
       RETURNING *`,
      [status, id]
    );
    if (!result.rows.length)
      return res.status(404).json({ error: "Gift order topilmadi" });

    if (['completed', 'delivered', 'failed', 'error', 'expired', 'cancelled', 'processing'].includes(status)) {
      releaseGiftPriceSlotByOrderId(result.rows[0].id);
      removePriceFromCacheByOrderId(result.rows[0].id);
    }
    
    res.json({ success: true, updated: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/admin/gift/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});
// ======================
// 🎁 ADMIN — Gift qayta yuborish
// ======================
app.post("/api/admin/gift/send/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto'g'ri" });
    const q = await pool.query("SELECT * FROM orders WHERE id = $1 AND order_type='gift'", [id]);
    if (!q.rows.length) return res.status(404).json({ error: "Gift order topilmadi" });
    const order = q.rows[0];
    if (order.status === "completed") {
      return res.status(400).json({ error: "Gift allaqachon yuborilgan" });
    }
    await sendGiftToUser(order);
    res.json({ success: true, message: "Gift yuborildi" });
  } catch (err) {
    console.error("❌ ADMIN GIFT SEND ERROR:", err);
    res.status(500).json({ error: "Server xatosi", details: err.message });
  }
});
// ======================
// 📊 ADMIN — Wallet Info (TON Balance & Stars Price)
// ======================
const ROBYNHOOD_API_KEY = process.env.ROB_API_KEY;
app.get("/api/admin/wallet-info", adminAuth, async (req, res) => {
  try {
    // Fetch TON balance
    const balanceRes = await fetch("https://robynhood.parssms.info/api/balance", {
      headers: {
        "accept": "application/json",
        "X-API-Key": ROBYNHOOD_API_KEY
      }
    });
    const balanceData = await balanceRes.json();
    // Fetch stars price (50 stars as reference)
    const priceRes = await fetch("https://robynhood.parssms.info/api/prices?product_type=stars&quantity=50", {
      headers: {
        "accept": "application/json",
        "X-API-Key": ROBYNHOOD_API_KEY
      }
    });
    const priceData = await priceRes.json();
    // Calculate available stars
    const mainnetBalance = parseFloat(balanceData.mainnet_balance) || 0;
    const testnetBalance = parseFloat(balanceData.testnet_balance) || 0;
    const priceFor50Stars = parseFloat(priceData.price) || 0;
    const pricePerStar = priceFor50Stars / 50;
    const availableStars = pricePerStar > 0 ? Math.floor(mainnetBalance / pricePerStar) : 0;
    res.json({
      success: true,
      wallet: {
        mainnet_balance: mainnetBalance,
        testnet_balance: testnetBalance
      },
      stars_price: {
        price_for_50: priceFor50Stars,
        price_per_star: pricePerStar,
        currency: priceData.currency || "TON"
      },
      available_stars: availableStars
    });
  } catch (err) {
    console.error("❌ /api/admin/wallet-info ERROR:", err);
    res.status(500).json({ error: "Failed to fetch wallet info" });
  }
});

// ======================
// ⭐ ADMIN — User Stars Balance (Userbot GramJS orqali)
// ======================
app.get("/api/admin/bot-stars-balance", adminAuth, async (req, res) => {
  try {
    // Userbot orqali stars balance olish
    console.log(`📡 Bot stars balance so'ralmoqda... (INTERNAL_SECRET=${INTERNAL_SECRET ? 'set' : 'NOT SET'})`);
    const response = await fetch(`${BALANCE_CHECKER_URL}/api/userbot/stars-balance`, {
      method: 'GET',
      headers: {
        'X-Internal-Key': INTERNAL_SECRET
      }
    });
    
    console.log(`📡 Balance checker response status: ${response.status}`);
    const data = await response.json();
    console.log(`📡 Balance checker response (stars_balance):`, data.stars_balance);
    
    if (!data.success) {
      console.log("⚠️ Userbot stars balance xato:", data.error);
      return res.json({
        success: true,
        bot_stars_balance: 0,
        transactions_available: false,
        message: data.error || "Stars balance olishda xato"
      });
    }

    // Natijani qaytarish
    res.json({
      success: true,
      bot_stars_balance: data.stars_balance || 0,
      transactions_available: true
    });

  } catch (err) {
    console.error("❌ /api/admin/bot-stars-balance ERROR:", err);
    res.json({
      success: true,
      bot_stars_balance: 0,
      transactions_available: false,
      message: "Userbot ulanmagan"
    });
  }
});
// ==============================================
// 📦 UNIFIED ORDER SYSTEM — Yangi optimallashtirilgan tizim
// ==============================================
// 🔧 Unique summ generatsiya qiluvchi funksiya (20ta slot -50 so'mdan)
async function generateUniqueOrderSum(baseAmount, client) {
  const maxSlots = 21; // 0 dan 20 gacha jami 21 xil narx (baseAmount dan to baseAmount - 1000 gacha)
  const slotCandidates = [];
  
  for (let i = 0; i < maxSlots; i++) {
    slotCandidates.push(baseAmount - (i * 50));
  }

  let selectedSum = null;

  for (const candidate of slotCandidates) {
    // 1-qadam: Global cachedan tekshirish
    if (isPriceUsed(candidate)) {
      continue;
    }
    
    // 2-qadam: Baza orqali (pending orderlar ichida) qat'iy tekshirish
    const finalCheck = await client.query(
      "SELECT id FROM orders WHERE summ = $1 AND (status = 'pending' OR payment_status = 'pending') LIMIT 1",
      [candidate]
    );

    if (finalCheck.rows.length === 0) {
      selectedSum = candidate;
      break;
    } else {
      // Agar bazada topilib, lekin cache'da yo'q bo'lsa, xavfsizlik uchun cache'ni yangilaymiz
      addPriceToCache(candidate, 'db_ghost_' + Date.now(), 'temp');
    }
  }

  if (selectedSum === null) {
    throw new Error("Tizimda order ko'p 5 daqiqada qayta urinib ko'ring");
  }

  return selectedSum;
}
// 📦 UNIFIED ORDER CREATE — Stars, Premium, Gift uchun yagona endpoint
app.post("/api/v2/order/create", orderLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 📦 UNIFIED ORDER CREATE ===============");
    console.log("📥 Keldi:", req.body);

    const maxPendingOrders = 3;
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    if (tgUserId) {
        const activeOrdersRes = await pool.query(
          `SELECT COUNT(*) as count FROM orders WHERE owner_user_id = $1 AND status = 'pending' AND payment_status = 'pending'`,
          [tgUserId]
        );
        if (parseInt(activeOrdersRes.rows[0].count) >= maxPendingOrders) {
          return res.status(429).json({ error: "Sizda to'lanmagan buyurtmalar mavjud. Iltimos oldin ularni to'lang yoki biroz kuting." });
        }
    }

    let {
      order_type,       // 'stars', 'premium', 'gift'
      recipient_username,
      recipient,        // provider recipient ID
      type_amount,      // stars soni, oy soni, yoki gift stars soni
      payment_method,   // 'card', 'click', 'payme'
      gift_id,          // gift order uchun
      gift_anonymous,   // gift order uchun
      gift_comment      // gift order uchun
    } = req.body;
    
    // Telegram user ma'lumotlari
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;
    
    // Validatsiya
    if (!order_type || !['stars', 'premium', 'gift'].includes(order_type)) {
      return res.status(400).json({ error: "order_type kerak: 'stars', 'premium', yoki 'gift'" });
    }
    
    if (!recipient) {
      return res.status(400).json({ error: "recipient kerak" });
    }
    
    if (!type_amount || type_amount <= 0 || !Number.isInteger(Number(type_amount))) {
      return res.status(400).json({ error: "type_amount butun son bo'lishi kerak va 0 dan katta bo'lishi kerak" });
    }
    
    // type_amount ni aniq raqam (number) formatiga o'tkazib olish
    type_amount = Number(type_amount);
    
    // Narxni hisoblash
    let baseSum = 0;
    
    if (order_type === 'stars') {
      // Stars miqdorini tekshirish (50-10000)
      if (type_amount < 50 || type_amount > 10000) {
        return res.status(400).json({ error: "Stars miqdori 50 dan 10000 gacha bo'lishi kerak" });
      }
      
      // Chegirma paketi tekshirish
      const discountCheck = await pool.query(
        "SELECT * FROM discount_packages WHERE stars = $1 AND is_active = true",
        [type_amount]
      );
      
      if (discountCheck.rows.length > 0) {
        baseSum = discountCheck.rows[0].discounted_price;
        console.log(`🏷️ Chegirma paketi: ${type_amount} stars = ${baseSum} so'm`);
      } else {
        baseSum = type_amount * STARS_PRICE_PER_UNIT;
      }
      
    } else if (order_type === 'premium') {
      // Premium oy tekshirish
      if (![3, 6, 12].includes(type_amount)) {
        return res.status(400).json({ error: "Premium muddat 3, 6, yoki 12 oy bo'lishi kerak" });
      }
      
      const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
      baseSum = priceMap[type_amount];
      
      if (!baseSum) {
        return res.status(400).json({ error: "Premium narxi topilmadi" });
      }
      
    } else if (order_type === 'gift') {
      // Gift stars tekshirish
      if (!gift_id) {
        return res.status(400).json({ error: "gift_id kerak" });
      }
      
      const serverStars = GIFT_STARS_MAP[gift_id];
      if (!serverStars) {
        return res.status(400).json({ error: "Noto'g'ri gift ID yuborildi" });
      }

      // 🛡️ XAVFSIZLIK: Mijoz yuborgan type_amount ga ishonmasdan, 
      // bazadagi (GIFT_STARS_MAP) haqiqiy narx (stars) bo'yicha hisoblaymiz.
      type_amount = serverStars;
      baseSum = type_amount * STARS_PRICE_PER_UNIT;
    }
    
    console.log(`💰 Hisoblangan narx: ${baseSum} so'm`);
    
    // Transaction bilan unique sum generatsiya
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1004)'); // Unified orders uchun alohida lock
      
      const uniqueSum = await generateUniqueOrderSum(baseSum, client);
      console.log(`✅ Unique summ: ${uniqueSum} so'm`);
      
      // Orderni yaratish
      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders (
          order_id, owner_user_id, recipient_username, recipient, order_type, 
          type_amount, summ, payment_method, payment_status, status,
          gift_id, gift_anonymous, gift_comment, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 'pending', $9, $10, $11, NOW())
        RETURNING *`,
        [
          orderId,
          ownerUserId,
          recipient_username || null,
          recipient,
          order_type,
          type_amount,
          uniqueSum,
          payment_method || 'card',
          gift_id || null,
          gift_anonymous || false,
          gift_comment || null
        ]
      );
      
      await client.query('COMMIT');
      order = result.rows[0];
      
      // 🔄 Global cache ga qo'shish
      addPriceToCache(order.summ, order.id, order.order_type);
      
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    
    console.log(`🎉 Order yaratildi: #${order.id} | ${order.order_type} | ${order.summ} so'm`);
    
    // Balance checker ga signal
    try {
      fetch(`${INTERNAL_API_BASE}/api/balance/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }
    
    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status, order_type FROM orders WHERE id = $1",
          [order.id]
        );
        
        if (check.rows[0]?.status === 'pending') {
          await pool.query(
            "UPDATE orders SET status = 'expired', payment_status = 'expired' WHERE id = $1",
            [order.id]
          );
          
          const orderType = check.rows[0].order_type;
          if (orderType === 'stars') {
            releasePriceSlotByOrderId(order.id);
            releaseDiscountPriceSlotByOrderId(order.id);
          } else if (orderType === 'premium') {
            releasePremiumPriceSlotByOrderId(order.id);
          } else if (orderType === 'gift') {
            releaseGiftPriceSlotByOrderId(order.id);
          }
          
          // 🔄 Cache dan o'chirish
          removePriceFromCacheByOrderId(order.id);
          
          console.log(`⏰ Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Order expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);
    
    res.json({ success: true, order });
    
  } catch (err) {
    console.error("❌ UNIFIED ORDER CREATE ERROR:", err);
    res.status(500).json({ error: "Server xato", details: err.message });
  }
});
// 📋 ORDER STATUS — Order holatini olish
app.get("/api/v2/order/:id", telegramAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: "ID noto'g'ri" });
    }
    
    const result = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [Number(id)]
    );
    
    if (!result.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    res.json(result.rows[0]);
    
  } catch (err) {
    console.error("❌ ORDER GET ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 💳 UNIFIED PAYMENT MATCH — To'lov tasdiqlanishi
app.post("/api/v2/payments/match", internalAuth, async (req, res) => {
  try {
    console.log("\n=============== 💳 UNIFIED PAYMENT MATCH ===============");
    console.log("📥 Keldi:", req.body);
    
    const { amount, card_last4 } = req.body;
    
    if (!amount) {
      return res.status(400).json({ error: "amount kerak" });
    }
    
    // Atomic update — race condition oldini olish
    const updated = await pool.query(
      `UPDATE orders 
       SET payment_status = 'completed'
       WHERE id = (
         SELECT id FROM orders 
         WHERE summ = $1 
           AND payment_status = 'pending' 
           AND status = 'pending'
           AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '15 minutes'
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    
    if (!updated.rows.length) {
      console.log("❌ Pending order TOPILMADI summ:", amount);
      return res.status(404).json({ error: "Pending order topilmadi" });
    }
    
    const order = updated.rows[0];
    console.log(`🎯 Order topildi: #${order.id} | ${order.order_type}`);
    
    // Order turига qarab yetkazish
    let deliveryResult;
    
    try {
      if (order.order_type === 'stars') {
        deliveryResult = await deliverStarsOrder(order);
      } else if (order.order_type === 'premium') {
        deliveryResult = await deliverPremiumOrder(order);
      } else if (order.order_type === 'gift') {
        deliveryResult = await sendGiftToUser(order);
      }
      
      console.log("📦 Delivery natijasi:", deliveryResult);
      
    } catch (deliveryErr) {
      console.error("❌ Delivery xatosi:", deliveryErr.message);
      await pool.query(
        "UPDATE orders SET status = 'error' WHERE id = $1",
        [order.id]
      );
      // 🔥 Xato bo'lsa ham slot va keshlarni bo'shatish
      releasePriceSlotByOrderId(order.id);
      releaseDiscountPriceSlotByOrderId(order.id);
      releasePremiumPriceSlotByOrderId(order.id);
      releaseGiftPriceSlotByOrderId(order.id);
      removePriceFromCacheByOrderId(order.id);
      
      // 📢 Umumiy xato kanalga xabarnoma (agar quyi qatlam xabar yubormagan bo'lsa)
      if (!deliveryErr.notified) {
        sendUnifiedChannelNotification(order, order.order_type, true).catch(err => console.error("Notif err:", err.message));
      }
      
      return res.json({ 
        success: false, 
        order_id: order.id, 
        error: deliveryErr.message 
      });
    }
    
    res.json({ 
      success: true, 
      order_id: order.id,
      order_type: order.order_type,
      delivery: deliveryResult 
    });
    
  } catch (err) {
    console.error("❌ UNIFIED PAYMENT MATCH ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🌟 Stars yetkazish funksiyasi
async function deliverStarsOrder(order) {
  console.log(`🌟 Stars yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "stars",
      recipient: order.recipient,
      quantity: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Stars API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Stars API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    // 🎯 Slotni bo'shatish - failed
    releasePriceSlotByOrderId(order.id);
    releaseDiscountPriceSlotByOrderId(order.id);
    removePriceFromCacheByOrderId(order.id);
    
    // 📢 Xato kanalga xabar
    sendUnifiedChannelNotification(order, 'stars', true).catch(err => console.error("Notif err:", err.message));
    
    const err = new Error("Stars yuborishda xato: " + JSON.stringify(data));
    err.notified = true;
    throw err;
  }
  
  // Muvaffaqiyatli — statusni yangilash
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  // 🎯 Slotni bo'shatish - completed
  releasePriceSlotByOrderId(order.id);
  releaseDiscountPriceSlotByOrderId(order.id);
  removePriceFromCacheByOrderId(order.id);
  
  console.log(`✅ Stars yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Referral bonus
  if (order.owner_user_id) {
    processReferralBonusByUserId(order.owner_user_id, order.type_amount, order.id)
      .catch(err => console.error("❌ Referral bonus error:", err.message));
  }
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'stars').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 👑 Premium yetkazish funksiyasi
async function deliverPremiumOrder(order) {
  console.log(`👑 Premium yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "premium",
      recipient: order.recipient,
      months: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Premium API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Premium API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    // 🎯 Slotni bo'shatish - failed
    releasePremiumPriceSlotByOrderId(order.id);
    removePriceFromCacheByOrderId(order.id);
    
    // 📢 Xato kanalga xabar
    sendUnifiedChannelNotification(order, 'premium', true).catch(err => console.error("Notif err:", err.message));
    
    const err = new Error("Premium yuborishda xato: " + JSON.stringify(data));
    err.notified = true;
    throw err;
  }
  
  // Muvaffaqiyatli
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  // 🎯 Slotni bo'shatish - completed
  releasePremiumPriceSlotByOrderId(order.id);
  removePriceFromCacheByOrderId(order.id);
  
  console.log(`✅ Premium yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Premium referral bonus
  if (order.owner_user_id) {
    processPremiumReferralBonusByUserId(order.owner_user_id, order.id)
      .catch(err => console.error("❌ Premium referral bonus error:", err.message));
  }
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'premium').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 🎁 Gift yetkazish funksiyasi
async function deliverGiftOrder(order) {
  console.log(`🎁 Gift yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "gift",
      recipient: order.recipient,
      gift_id: order.gift_id,
      quantity: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Gift API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Gift API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    // 🎯 Slotni bo'shatish - failed
    releaseGiftPriceSlotByOrderId(order.id);
    removePriceFromCacheByOrderId(order.id);
    
    // 📢 Xato kanalga xabar
    sendUnifiedChannelNotification(order, 'gift', true).catch(err => console.error("Notif err:", err.message));
    
    const err = new Error("Gift yuborishda xato: " + JSON.stringify(data));
    err.notified = true;
    throw err;
  }
  
  // Muvaffaqiyatli
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  // 🎯 Slotni bo'shatish - completed
  releaseGiftPriceSlotByOrderId(order.id);
  removePriceFromCacheByOrderId(order.id);
  
  console.log(`✅ Gift yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'gift').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 📢 Unified kanal xabari
async function sendUnifiedChannelNotification(order, type, isFailed = false) {
  if (!bot) return;
  
  let emoji = isFailed ? '⚠️' : (type === 'premium' ? '👑' : type === 'gift' ? '🎁' : '🌟');
  let typeName = type === 'premium' ? 'Premium' : type === 'gift' ? 'Gift' : 'Stars';
  
  let title = isFailed 
    ? `<b>${typeName} xaridi muvaffaqiyatsiz bo'ldi!</b>` 
    : `<b>Yangi ${typeName} sotildi!</b>`;

  const statusText = isFailed 
    ? `❌ Status: To'langan, ammo yetkazilmadi (failed)` 
    : `✅ Status: Yetkazildi`;
    
  let senderUsername = "Noma'lum";
  if (order.owner_user_id) {
    try {
      const userRes = await pool.query("SELECT username FROM users WHERE user_id = $1", [order.owner_user_id]);
      if (userRes.rows.length > 0 && userRes.rows[0].username) {
        senderUsername = userRes.rows[0].username;
      }
    } catch (e) {
      console.error("Yuboruvchi aniqlashda xato:", e);
    }
  }

  const rawRecipient = order.recipient_username || order.recipient || "Noma'lum";
  const formattedSender = senderUsername.startsWith('@') ? senderUsername : `@${senderUsername}`;
  const formattedRecipient = rawRecipient.startsWith('@') ? rawRecipient : `@${rawRecipient}`;
  
  const message = `${emoji} ${title}\n\n` +
    `📦 Order: #${order.id}\n` +
    `👤 ${formattedSender} -> ${formattedRecipient}\n` +
    `💫 Miqdor: ${order.type_amount} ${type === 'premium' ? 'oy' : 'stars'}\n` +
    `💰 Summa: ${order.summ.toLocaleString()} so'm\n` +
    statusText;
  
  const targetChannel = isFailed ? ERROR_LOG_CHANNEL_ID : ORDERS_CHANNEL;
  
  try {
    await bot.telegram.sendMessage(targetChannel, message, { parse_mode: 'HTML' });
  } catch (err) {
    console.error("❌ Channel notification error:", err.message);
  }
}
// 🎁 Referral bonus user_id orqali
async function processReferralBonusByUserId(userId, stars, orderId) {
  try {
    // User ma'lumotlarini olish
    const userResult = await pool.query(
      "SELECT username, referrer_user_id FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    
    const username = userResult.rows[0].username;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    
    if (!referrerUserId) return;
    
    // Referrer username olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    
    if (referrerResult.rows.length === 0) return;
    
    const referrerUsername = referrerResult.rows[0].username;

    // Faqat 1 marta bonus berilishi tekshiruvi
    const checkGiven = await pool.query(
      `SELECT id FROM referral_earnings WHERE referrer_username = $1 AND referee_username = $2 LIMIT 1`,
      [referrerUsername, username]
    );
    if (checkGiven.rows.length > 0) return;
    
    // Istalgan stars olinganda qat'iy 5 stars beriladi
    const bonusStars = 5;
    
    // Referrer balance yangilash
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    
    // Referral earnings log
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, username, bonusStars, orderId]
    );
    
    console.log(`🎁 REFERRAL BONUS: ${referrerUsername} ga ${bonusStars}⭐ (order #${orderId})`);
    
  } catch (err) {
    console.error("❌ processReferralBonusByUserId error:", err.message);
  }
}
// 👑 Premium referral bonus user_id orqali
async function processPremiumReferralBonusByUserId(userId, orderId) {
  try {
    const userResult = await pool.query(
      "SELECT username, referrer_user_id FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    
    const username = userResult.rows[0].username;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    
    if (!referrerUserId) return;
    
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    
    if (referrerResult.rows.length === 0) return;
    
    const referrerUsername = referrerResult.rows[0].username;

    // Faqat 1 marta bonus berilishi tekshiruvi
    const checkGiven = await pool.query(
      `SELECT id FROM referral_earnings WHERE referrer_username = $1 AND referee_username = $2 LIMIT 1`,
      [referrerUsername, username]
    );
    if (checkGiven.rows.length > 0) return;

    const bonusStars = 15;
    
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, username, bonusStars, orderId]
    );
    
    console.log(`🎁 PREMIUM REFERRAL BONUS: ${referrerUsername} ga ${bonusStars}⭐ (order #${orderId})`);
    
  } catch (err) {
    console.error("❌ processPremiumReferralBonusByUserId error:", err.message);
  }
}
// 📋 ADMIN: Barcha orderlarni olish
app.get("/api/v2/admin/orders", adminAuth, async (req, res) => {
  try {
    const { status, order_type, limit = 100 } = req.query;
    
    let query = "SELECT * FROM orders WHERE 1=1";
    const params = [];
    
    if (status && status !== 'all') {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }
    
    if (order_type && order_type !== 'all') {
      params.push(order_type);
      query += ` AND order_type = $${params.length}`;
    }
    
    params.push(Number(limit));
    query += ` ORDER BY id DESC LIMIT $${params.length}`;
    
    const result = await pool.query(query, params);
    
    res.json({ success: true, orders: result.rows });
    
  } catch (err) {
    console.error("❌ ADMIN ORDERS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔄 ADMIN: Order status yangilash
app.patch("/api/v2/admin/orders/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, payment_status } = req.body;
    
    if (!id) {
      return res.status(400).json({ error: "ID kerak" });
    }
    
    const updates = [];
    const params = [];
    
    if (status) {
      params.push(status);
      updates.push(`status = $${params.length}`);
    }
    
    if (payment_status) {
      params.push(payment_status);
      updates.push(`payment_status = $${params.length}`);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: "Yangilanadigan ma'lumot kerak" });
    }
    
    params.push(Number(id));
    const query = `UPDATE orders SET ${updates.join(', ')} WHERE id = $${params.length} RETURNING *`;
    
    const result = await pool.query(query, params);
    
    if (!result.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    // Agar status yakuniy holatlardan biriga o'zgartirilgan bo'lsa, keshlarni tozalash (slot qotib qolmasligi uchun)
    if (status && ['completed', 'delivered', 'failed', 'error', 'expired', 'cancelled', 'processing'].includes(status)) {
      const orderId = result.rows[0].id;
      releasePriceSlotByOrderId(orderId);
      releaseDiscountPriceSlotByOrderId(orderId);
      releasePremiumPriceSlotByOrderId(orderId);
      releaseGiftPriceSlotByOrderId(orderId);
      removePriceFromCacheByOrderId(orderId);
    }
    
    res.json({ success: true, order: result.rows[0] });
    
  } catch (err) {
    console.error("❌ ADMIN ORDER UPDATE ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔄 ADMIN: Orderni qayta yetkazish
app.post("/api/v2/admin/orders/:id/redeliver", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [Number(id)]
    );
    
    if (!orderResult.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    const order = orderResult.rows[0];
    
    if (order.status === 'delivered') {
      return res.status(400).json({ error: "Order allaqachon yetkazilgan" });
    }
    
    let deliveryResult;
    
    if (order.order_type === 'stars') {
      deliveryResult = await deliverStarsOrder(order);
    } else if (order.order_type === 'premium') {
      deliveryResult = await deliverPremiumOrder(order);
    } else if (order.order_type === 'gift') {
      deliveryResult = await sendGiftToUser(order);
    }
    
    res.json({ success: true, delivery: deliveryResult });
    
  } catch (err) {
    console.error("❌ ADMIN REDELIVER ERROR:", err);
    res.status(500).json({ error: "Server xato", details: err.message });
  }
});
// 📊 ADMIN: Order statistikasi
app.get("/api/v2/admin/orders/stats", adminAuth, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        order_type,
        status,
        COUNT(*) as count,
        SUM(summ) as total_sum
      FROM orders
      GROUP BY order_type, status
      ORDER BY order_type, status
    `);
    
    const todayStats = await pool.query(`
      SELECT 
        order_type,
        COUNT(*) as count,
        SUM(summ) as total_sum
      FROM orders
      WHERE created_at >= CURRENT_DATE
      GROUP BY order_type
    `);
    
    res.json({
      success: true,
      all_time: stats.rows,
      today: todayStats.rows
    });
    
  } catch (err) {
    console.error("❌ ADMIN STATS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// 🔍 DEBUG ENDPOINT - Slot diagnostic
// ======================
app.get("/api/debug/slots", adminAuth, async (req, res) => {
  try {
    // In-memory slot holati
    const memorySlots = {};
    for (const key in priceSlots) {
      const slots = priceSlots[key];
      const slotDetails = {};
      for (const i in slots) {
        const elapsed = Date.now() - slots[i].createdAt;
        slotDetails[i] = {
          orderId: slots[i].orderId,
          elapsed: Math.round(elapsed / 1000) + "s",
          expired: elapsed > PRICE_SLOT_CONFIG.SLOT_TIMEOUT
        };
      }
      memorySlots[key] = {
        totalSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
        usedSlots: Object.keys(slots).length,
        slots: slotDetails
      };
    }
    
    // Database pending orders
    const dbPending = await pool.query(`
      SELECT order_type, type_amount, COUNT(*) as count,
             SUM(CASE WHEN created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes' THEN 1 ELSE 0 END) as recent_count
      FROM orders 
      WHERE status = 'pending' AND payment_status = 'pending'
      GROUP BY order_type, type_amount
      ORDER BY order_type, type_amount
    `);
    
    // Recent stars orders detail
    const recentStars = await pool.query(`
      SELECT id, type_amount as stars, summ, created_at,
             EXTRACT(EPOCH FROM (NOW() - created_at)) as age_seconds
      FROM orders 
      WHERE order_type = 'stars' AND status = 'pending' AND payment_status = 'pending'
      AND created_at >= (NOW() AT TIME ZONE 'Asia/Tashkent') - INTERVAL '8 minutes'
      ORDER BY type_amount, created_at
    `);
    
    res.json({
      timestamp: new Date().toISOString(),
      config: {
        maxSlots: PRICE_SLOT_CONFIG.MAX_SLOTS,
        slotTimeoutMinutes: PRICE_SLOT_CONFIG.SLOT_TIMEOUT / 60000
      },
      memorySlots: memorySlots,
      databasePending: dbPending.rows,
      recentStarsOrders: recentStars.rows.map(r => ({
        id: r.id,
        stars: r.stars,
        summ: r.summ,
        ageSeconds: Math.round(r.age_seconds)
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================
// run server
// ======================
// 🚀 Server start - cache ni yuklash
loadPendingOrdersToCache().then(() => {
  console.log(`✅ Cache yuklandi: ${globalUsedPrices.size} ta pending order`);
});

app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
