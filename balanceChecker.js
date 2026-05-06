import 'dotenv/config';
import { TelegramClient } from 'telegram';
import { Api } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { NewMessage } from 'telegram/events/index.js';
import fetch from 'node-fetch';
import express from 'express';

// ================== CONFIG ==================
const apiId = parseInt(process.env.TG_API_ID);
const apiHash = process.env.TG_API_HASH;
const stringSession = new StringSession(process.env.TG_SESSION);
const UZCARD_CHAT_ID = String(process.env.UZCARD_CHAT_ID);
const TARGET_CARD_SUFFIX = process.env.TARGET_CARD_SUFFIX?.replace(/\D/g, "").slice(-4);

const MATCH_API_STARS = process.env.MATCH_API_STARS;
const MATCH_API_PREMIUM = process.env.MATCH_API_PREMIUM;
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET || '';
const BALANCE_CHECKER_PORT = Number(process.env.BALANCE_CHECKER_PORT);

if (!process.env.INTERNAL_API_SECRET) {
    console.error('❌ OGOHLANTIRISH: INTERNAL_API_SECRET .env da yo\'q!');
    console.error('❌ SMS listener match API 403 beradi — backend bilan bir xil kalitni .env ga qo\'ying!');
}
if (!MATCH_API_STARS || !MATCH_API_PREMIUM) {
    console.error('❌ MATCH_API_STARS yoki MATCH_API_PREMIUM .env da yo\'q!');
}

// Telegram client (global)
let client = null;
let isClientReady = false;

// ================== SMS PAYMENT PARSER (UZCARD) ==================
function parsePayment(text) {
    if (!text) return null;

    // UzCard format: 💳 ***2022
    const cardMatch = text.match(/💳\s*\*{3}(\d{4})/);
    const card_last4 = cardMatch ? cardMatch[1] : null;

    // UzCard format: ➕ 11 000.00 UZS (probel=ming ajratgich, nuqta=decimal)
    // [\d ]+ — faqat raqam va oddiy probel (newline emas!)
    const amountMatch = text.match(/➕\s*([\d ]+(?:\.\d{2})?)\s*UZS/i);
    if (!amountMatch) return null;

    const amountRaw = amountMatch[1].replace(/\s/g, "");
    const amount = Math.floor(parseFloat(amountRaw));

    if (!card_last4 || !amount || amount <= 0) return null;

    return { card_last4, amount, raw_text: text };
}

// ================== AutoReconnect (exponential backoff) ==================
async function autoReconnect(clientInstance) {
    let backoff = 2000;
    const maxBackoff = 60000;

    while (true) {
        try {
            if (!clientInstance.connected) {
                console.warn("⚠️ [GramJS] Aloqa uzildi! Qayta ulanmoqda...");
                await clientInstance.connect();
                console.log("✅ [GramJS] Qayta ulandi!");
                backoff = 2000;
            }
        } catch (err) {
            console.error("❌ [GramJS] Qayta ulanish xatosi:", err?.message || err);
            await new Promise((r) => setTimeout(r, backoff));
            backoff = Math.min(backoff * 2, maxBackoff);
        }
        await new Promise((res) => setTimeout(res, 3000));
    }
}

// ================== TELEGRAM CLIENT INIT (FAQAT SMS LISTENER) ==================
export async function initBalanceClient() {
    if (isClientReady && client?.connected) {
        console.log('✅ SMS listener client allaqachon ulangan');
        return true;
    }

    console.log('🔄 GramJS client ulanmoqda (faqat SMS listener)...');

    client = new TelegramClient(stringSession, apiId, apiHash, {
        connectionRetries: 50,
    });

    await client.start({
        phoneNumber: async () => '',
        password: async () => '',
        phoneCode: async () => '',
        onError: (err) => console.log('GramJS client error:', err),
    });

    console.log('✅ GramJS client ulandi!');

    // UZCARD entity ni to'g'ridan-to'g'ri olish
    console.log('🔍 UZCARD chat qidirilmoqda... (ID:', UZCARD_CHAT_ID, ')');
    let uzcardEntity = null;

    // 1-usul: getEntity bilan to'g'ridan-to'g'ri olish
    try {
        uzcardEntity = await client.getEntity(parseInt(UZCARD_CHAT_ID));
        if (uzcardEntity) {
            console.log(`✅ UZCARD chat topildi (getEntity): ${uzcardEntity.firstName || uzcardEntity.title || uzcardEntity.username || 'N/A'}`);
        }
    } catch (e) {
        console.log('⚠️ getEntity bilan topilmadi, dialoglardan qidirilmoqda...');
    }

    // 2-usul: Dialoglardan qidirish (agar getEntity ishlamasa)
    if (!uzcardEntity) {
        try {
            const dialogs = await client.getDialogs({ limit: 500 });
            console.log(`📋 Jami ${dialogs.length} ta dialog yuklab olindi`);

            for (const d of dialogs) {
                const peerId = d.id?.value !== undefined ? String(d.id.value) : String(d.id);
                if (peerId === UZCARD_CHAT_ID || peerId === `-${UZCARD_CHAT_ID}`) {
                    uzcardEntity = d.entity;
                    console.log(`✅ UZCARD chat topildi (dialog): ${d.name || d.title} | ID: ${peerId}`);
                    break;
                }
            }
        } catch (e) {
            console.error('⚠️ Dialoglarni yuklashda xato:', e.message);
        }
    }

    // 3-usul: PeerUser/PeerChat sifatida
    if (!uzcardEntity) {
        try {
            const inputPeer = new Api.InputPeerUser({
                userId: parseInt(UZCARD_CHAT_ID),
                accessHash: BigInt(0),
            });
            uzcardEntity = await client.getEntity(inputPeer);
            if (uzcardEntity) {
                console.log(`✅ UZCARD chat topildi (InputPeerUser): ${uzcardEntity.firstName || uzcardEntity.title || 'N/A'}`);
            }
        } catch (e) {
            console.log('⚠️ InputPeerUser bilan ham topilmadi:', e.message);
        }
    }

    if (!uzcardEntity) {
        console.error('❌ UZCARD chat topilmadi! ID:', UZCARD_CHAT_ID);
        console.error('💡 To\'g\'ri UZCARD_CHAT_ID .env da belgilanganligini tekshiring');
        // Entity topilmasa ham listener ni ishga tushiramiz — peerId orqali filtrlaydi
        console.log('⚠️ Entity topilmadi, lekin SMS listener baribir peerId orqali ishlaydi');
    }

    // ================== SMS PAYMENT HANDLER ==================
    console.log('📡 UZCARD SMS listener ishga tushmoqda...');

    const ORDERS_CHANNEL = String(process.env.ORDERS_CHANNEL || "-1003986767336");
    const ERROR_LOG_CHANNEL_ID = String(process.env.ERROR_LOG_CHANNEL_ID || "-1003963671866");
    const BOT_TOKEN = process.env.BOT_TOKEN;
    const pendingUzcardPayments = []; // monitoring uchun

    const MONITORED_CHANNELS = [ORDERS_CHANNEL];
    console.log(`📡 Monitoring kanal: ORDERS=${ORDERS_CHANNEL}`);

    client.addEventHandler(
        async (event) => {
            try {
                const msg = event.message;
                if (!msg) return;

                const rawPeerId =
                    msg.peerId?.channelId ??
                    msg.peerId?.chatId ??
                    msg.peerId?.userId;

                const peerId = rawPeerId?.value !== undefined ? String(rawPeerId.value) : String(rawPeerId);

                const text = msg.message || "";

                // ==========================================
                // 📡 ORDERS_CHANNEL — order summasini SMS to'lovi bilan bog'lash
                // ==========================================
                // Channel ID ni normalize qilish (har xil formatlarni qo'llab-quvvatlash)
                const normalizeChannelId = (id) => String(id).replace(/^-100/, '').replace(/^-/, '');
                const normalizedPeerId = normalizeChannelId(peerId);
                
                const isMonitoredChannel = MONITORED_CHANNELS.some(ch => 
                    normalizeChannelId(ch) === normalizedPeerId
                );

                if (isMonitoredChannel) {
                    // 💰 Summa: 175,000 so'm formatidan summa ajratish
                    // Turli formatlarni qo'llab-quvvatlash: 175,000 | 175 000 | 175.000
                    const sumMatch = text.match(/💰\s*Summa:\s*([\d,.\s\u00A0]+)\s*so['']?m/i);
                    if (sumMatch) {
                        // Barcha raqam bo'lmagan belgilarni olib tashlash
                        const orderSum = parseInt(sumMatch[1].replace(/[^\d]/g, ''), 10);
                        if (orderSum && orderSum > 0) {
                            console.log(`✅ [ORDERS_CHANNEL] Order sum detected: ${orderSum} so'm`);
                            const matchIndex = pendingUzcardPayments.findIndex(p => p.amount === orderSum);
                            if (matchIndex !== -1) {
                                pendingUzcardPayments.splice(matchIndex, 1);
                                console.log(`✅ [Monitoring] ${orderSum} so'm to'lov o'z egasini topdi (ORDERS kanalda).`);
                            }
                        }
                    }
                    return;
                }

                if (peerId !== UZCARD_CHAT_ID) return;

                console.log("📩 [UZCARD SMS] Xabar keldi:", {
                    peerId,
                    text: msg.message,
                });

                if (!text.includes("➕")) return;
                if (!text.includes(TARGET_CARD_SUFFIX)) return;

                const parsed = parsePayment(text);
                if (!parsed) return;

                console.log("💳 To'lov aniqlandi:", parsed);

                // Monitoring uchun qo'shish
                pendingUzcardPayments.push({
                    amount: parsed.amount,
                    text: parsed.raw_text,
                    timestamp: Date.now()
                });

                // Stars API — faqat stars buyurtmasi (bir xil summali premium bilan aralashmasin)
                let res = await fetch(MATCH_API_STARS, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Internal-Key": INTERNAL_SECRET
                    },
                    body: JSON.stringify({
                        ...parsed,
                        allowed_order_types: ["stars"],
                    }),
                });

                if (!res.ok) {
                    const errBody = await res.text().catch(() => "");
                    console.log(
                        `⭐ Stars match muvaffaqiyatsiz HTTP ${res.status} → PREMIUM urinyapti...`,
                        errBody ? errBody.slice(0, 300) : ""
                    );
                    res = await fetch(MATCH_API_PREMIUM, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-Internal-Key": INTERNAL_SECRET
                        },
                        body: JSON.stringify(parsed),
                    });
                }

                if (res.ok) {
                    const result = await res.json();
                    console.log("🎉 Muvaffaqiyatli topildi:", result);
                } else {
                    const premBody = await res.text().catch(() => "");
                    console.log(
                        "⭐💎 Stars va Premium bazasida mos buyurtma topilmadi:",
                        premBody ? premBody.slice(0, 300) : ""
                    );
                }
            } catch (err) {
                console.error("❌ SMS Handler xatosi:", err);
            }
        },
        new NewMessage({})
    );

    // Timer (Har 1 daqiqada tekshiradi)
    setInterval(() => {
        const now = Date.now();
        for (let i = pendingUzcardPayments.length - 1; i >= 0; i--) {
            const p = pendingUzcardPayments[i];
            // 5 daqiqadan oshgan bo'lsa (5 * 60 * 1000 = 480000 ms)
            if (now - p.timestamp > 480000) {
                console.log(`⚠️ Tizimda qolib ketgan to'lov (${p.amount})! ORDERS kanalida topilmadi - Error kanalga yuborilmoqda...`);
                
                if (BOT_TOKEN && ERROR_LOG_CHANNEL_ID) {
                    const message = `⚠️ <b>XATO tolov - 5 daqiqa ichida topilmadi</b>\n\n📝 <b>To'lov xabari:</b>\n<code>${p.text}</code>\n\n💰 <b>Summa:</b> ${p.amount.toLocaleString()} so'm\n\n📡 <b>Kuzatilgan kanal:</b> ORDERS_CHANNEL\n\n📌 Bu summaga mos order ORDERS kanalida topilmadi!\nIltimos, bu to'lov nima uchun kelganini tekshiring!`;
                    fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: ERROR_LOG_CHANNEL_ID,
                            text: message,
                            parse_mode: 'HTML'
                        })
                    }).catch(e => console.error("Error kanalga SMS jo'natish xatosi:", e));
                }

                pendingUzcardPayments.splice(i, 1);
            }
        }
    }, 60000);

    console.log('✅ UZCARD SMS listener tayyor! (ORDERS kanal monitoring)');

    // AutoReconnect ni background da ishga tushirish
    autoReconnect(client).catch((e) => console.error("autoReconnect failed:", e));

    isClientReady = true;
    return true;
}

// ================== START (faqat SMS listener) ==================
export async function startBalanceChecker() {
    console.log('🚀 SMS Listener ishga tushmoqda...');

    const ok = await initBalanceClient();
    if (!ok) {
        console.error('❌ SMS Listener client ulanmadi!');
        return false;
    }

    console.log('✅ SMS Listener tayyor — to\'lovlarni kutmoqda...');
    return true;
}

// ================== DISCONNECT ==================
export async function disconnectBalanceClient() {
    if (client) {
        await client.disconnect();
        isClientReady = false;
        console.log('🔌 SMS Listener client uzildi');
    }
}

// ================== HTTP SERVER ==================
const app = express();
app.use(express.json());

// Status endpoint
app.get('/api/balance/status', (req, res) => {
    res.json({
        success: true,
        clientReady: isClientReady,
        mode: 'sms-only'
    });
});

// ======================
// 🎁 GIFT SEND — Userbot (GramJS) orqali gift yuborish
// ======================
app.post('/api/gift/send-userbot', async (req, res) => {
    try {
        // Internal auth tekshiruvi
        const key = req.headers['x-internal-key'];
        if (key !== INTERNAL_SECRET) {
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        const { recipientUsername, giftId, message, anonymous } = req.body;

        if (!recipientUsername || !giftId) {
            return res.status(400).json({ success: false, error: 'recipientUsername va giftId kerak' });
        }

        const cleanUsername = recipientUsername.startsWith('@')
            ? recipientUsername.slice(1)
            : recipientUsername;

        console.log(`🎁 Gift yuborilmoqda: @${cleanUsername} | gift: ${giftId} | anonim: ${anonymous}`);

        // Username orqali InputPeer olish
        let inputPeer;
        try {
            inputPeer = await client.getInputEntity(cleanUsername);
        } catch (err) {
            console.error("❌ getInputEntity xatosi:", err.message);
            return res.status(404).json({ success: false, error: 'User Telegram bazasidan topilmadi. Ular botga profil ochiqligini tekshirishlari yoki maxfiylik sozlamalarini to\'g\'irlashlari kerak.' });
        }

        if (!inputPeer || !inputPeer.userId) {
            return res.status(404).json({ success: false, error: 'User Telegram bazasidan topilmadi. Ular userbotda kontakt yoki xabar tarixida bo\'lishi kerak.' });
        }

        // InputInvoiceStarGift yaratish
        const invoiceParams = {
            peer: inputPeer,
            giftId: BigInt(giftId),
            hideName: anonymous === true,
        };

        // Message (izoh) qo'shish
        if (message && message.trim()) {
            invoiceParams.message = new Api.TextWithEntities({
                text: message.trim(),
                entities: [],
            });
        }

        const invoice = new Api.InputInvoiceStarGift(invoiceParams);

        // 1. Payment form olish
        const paymentForm = await client.invoke(
            new Api.payments.GetPaymentForm({ invoice })
        );

        console.log(`💳 Payment form olindi: formId=${paymentForm.formId}`);

        // 2. Stars bilan to'lash (userbot balansidan)
        const result = await client.invoke(
            new Api.payments.SendStarsForm({
                formId: paymentForm.formId,
                invoice,
            })
        );

        console.log(`✅ Gift muvaffaqiyatli yuborildi: @${cleanUsername}`, result);

        res.json({ success: true, result });

    } catch (err) {
        console.error('❌ Gift yuborish xatosi:', err);

        // Telegram xato kodlarini qaytarish
        const errorMessage = err?.message || err?.errorMessage || 'Noma\'lum xato';
        res.status(500).json({ success: false, error: errorMessage });
    }
});

// ======================
// ⭐ STARS BALANCE — GramJS orqali user stars balansini olish
// ======================
app.get('/api/userbot/stars-balance', async (req, res) => {
    try {
        // Internal auth tekshiruvi
        const key = req.headers['x-internal-key'];
        console.log(`📡 /api/userbot/stars-balance so'rov keldi. Key: ${key ? 'provided' : 'NOT PROVIDED'}`);
        console.log(`📡 Expected: ${INTERNAL_SECRET ? 'CONFIGURED' : 'NOT CONFIGURED'}`);
        
        if (key !== INTERNAL_SECRET) {
            console.error(`❌ Key mos kelmadi! Received: ${key}, Expected: ${INTERNAL_SECRET}`);
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            console.error(`❌ Client tayyor emas! isClientReady=${isClientReady}, connected=${client?.connected}`);
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        console.log('⭐ Stars balance so\'ralmoqda...');

        // payments.getStarsStatus API
        const result = await client.invoke(
            new Api.payments.GetStarsStatus({
                peer: "me"
            })
        );

        console.log(`📊 Balance object:`, result.balance);
        console.log(`📊 Balance type:`, typeof result.balance);
        console.log(`📊 Balance keys:`, result.balance ? Object.keys(result.balance) : "null");

        // Balance ni olish
        let balance;
        if (result.balance && typeof result.balance === 'object') {
            // StarsAmount obyekti bo'lsa
            balance = result.balance.amount || result.balance.value || result.balance;
        } else {
            balance = result.balance;
        }
        
        // BigInt yoki Number ga aylantirish
        if (typeof balance === 'bigint') {
            balance = Number(balance);
        } else if (typeof balance === 'object' && balance?.value) {
            // Integer { value: 165n } formatida bo'lsa
            balance = Number(balance.value);
        } else if (typeof balance === 'object') {
            balance = 0;
        } else {
            balance = Number(balance) || 0;
        }

        console.log(`⭐ Stars balance (final): ${balance}`);

        res.json({
            success: true,
            stars_balance: balance,
            subscriptions: result.subscriptions || []
        });

    } catch (err) {
        console.error('❌ Stars balance olishda xato:', err);
        console.error('❌ Error stack:', err?.stack);
        res.status(500).json({ success: false, error: err?.message || 'Noma\'lum xato', details: err?.toString() });
    }
});

// ⭐ ALTERNATIVE - User profile orqali stars bilish
app.get('/api/userbot/user-me', async (req, res) => {
    try {
        const key = req.headers['x-internal-key'];
        if (key !== INTERNAL_SECRET) {
            return res.status(403).json({ success: false, error: 'Ruxsat berilmagan' });
        }

        if (!isClientReady || !client?.connected) {
            return res.status(503).json({ success: false, error: 'Userbot client tayyor emas' });
        }

        console.log('👤 Me orqali ma\'lumot olish...');

        // User info olish
        const me = await client.getMe();
        console.log('👤 User info:', me);
        console.log('👤 Me keys:', Object.keys(me || {}));

        res.json({
            success: true,
            user: me,
            username: me?.username,
            firstName: me?.firstName,
            id: me?.id
        });

    } catch (err) {
        console.error('❌ User me olishda xato:', err);
        res.status(500).json({ success: false, error: err?.message || 'Noma\'lum xato' });
    }
});

// ================== STANDALONE RUN ==================
if (process.argv[1]?.includes('balanceChecker')) {
    console.log('🚀 SMS Listener mustaqil ishga tushmoqda...');

    app.listen(BALANCE_CHECKER_PORT, () => {
        console.log(`🌐 SMS Listener HTTP server: http://localhost:${BALANCE_CHECKER_PORT}`);
    });

    startBalanceChecker()
        .then(() => {
            console.log('✅ SMS Listener muvaffaqiyatli ishga tushdi!');
        })
        .catch((err) => {
            console.error('❌ SMS Listener ishga tushmadi:', err);
            process.exit(1);
        });

    process.on('SIGINT', async () => {
        console.log('\n🛑 Shutdown signal olindi...');
        await disconnectBalanceClient();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n🛑 Terminate signal olindi...');
        await disconnectBalanceClient();
        process.exit(0);
    });
}
