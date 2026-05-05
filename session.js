/**
 * GramJS (telegram) orqali yangi sessiya olish.
 * .env da TG_API_ID va TG_API_HASH bo'lishi kerak.
 *
 * Ishlatish: node session.js   yoki   npm run session
 */

import 'dotenv/config';
import readlineSync from 'readline-sync';
import { TelegramClient } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';

const apiId = parseInt(process.env.TG_API_ID, 10);
const apiHash = process.env.TG_API_HASH;

if (!apiId || !apiHash) {
  console.error("❌ .env da TG_API_ID va TG_API_HASH majburiy.");
  process.exit(1);
}

const stringSession = new StringSession('');
const client = new TelegramClient(stringSession, apiId, apiHash, {
  connectionRetries: 5,
});

function askPhone() {
  const raw = readlineSync.question(
    "Telefon raqami ( xalqaro format, masalan +998901234567 ): "
  );
  return String(raw).trim();
}

async function main() {
  console.log("📱 Telegram akkauntiga kirish — kod SMS yoki Telegram ilovasida keladi.\n");

  try {
    await client.start({
      phoneNumber: askPhone,
      password: async (hint) => {
        const label = hint
          ? `2FA parol (Telegram hint: ${hint}) — bo'lmasa Enter: `
          : "2FA parol — bo'lmasa Enter: ";
        const p = readlineSync.question(label, { hideEchoBack: true });
        return String(p).trim();
      },
      phoneCode: async (isCodeViaApp) => {
        if (isCodeViaApp) {
          console.log("ℹ️ Kod Telegram ilovangizdagi xabarlarda.");
        } else {
          console.log("ℹ️ Kod SMS orqali keladi.");
        }
        const c = readlineSync.question("Telegram kodini kiriting: ");
        return String(c).replace(/\s/g, "").trim();
      },
      onError: (err) => {
        console.error("⚠️", err?.message || err);
        const retry = readlineSync.keyInYNStrict("Qayta urinilsinmi? ");
        return !retry;
      },
    });

    const saved = stringSession.save();
    if (!saved) {
      console.error("❌ Session saqlanmadi (bo'sh).");
      process.exit(1);
    }

    console.log("\n✅ Muvaffaqiyatli. Quyidagi qatorni backend .env ga qo'shing:\n");
    console.log("TG_SESSION=" + saved + "\n");
  } catch (e) {
    console.error("❌", e?.message || e);
    process.exit(1);
  } finally {
    try {
      await client.disconnect();
    } catch (_) {}
  }
}

main();
