import { Resend } from 'resend';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

// Load environment variables from apps/web/.env
dotenv.config({ path: path.join(__dirname, '../apps/web/.env') });

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || 'NEXUS Store <onboarding@resend.dev>';
const TO_EMAIL = 'caspertech92@gmail.com';

const BRIEF_PATH = '/home/redbend/.gemini/antigravity/brain/ce9ea8a7-2da2-4b1b-9688-650ea3826461/project_brief.md';

async function main() {
    if (!RESEND_API_KEY) {
        console.error('❌ Error: RESEND_API_KEY is not defined in environment variables.');
        process.exit(1);
    }

    if (!fs.existsSync(BRIEF_PATH)) {
        console.error(`❌ Error: Brief file not found at ${BRIEF_PATH}`);
        process.exit(1);
    }

    const resend = new Resend(RESEND_API_KEY);
    const content = fs.readFileSync(BRIEF_PATH, 'utf-8');

    console.log(`📡 Sending project brief to ${TO_EMAIL}...`);

    try {
        const { data, error } = await resend.emails.send({
            from: EMAIL_FROM,
            to: TO_EMAIL,
            subject: 'NEXUS 2027: Project Executive Brief 🚀',
            text: content,
            html: `
        <div style="background:#000; color:#fff; padding:40px; font-family: sans-serif; border-radius:16px;">
          <h1 style="color:#06b6d4;">NEXUS Executive Brief</h1>
          <p style="color:#6b7280;">Autonomous AI Marketplace — 2027 System Report</p>
          <hr style="border:1px solid #1a1a1a; margin: 20px 0;">
          <div style="white-space: pre-wrap; font-family: monospace; background: #0a0a0a; padding: 20px; border-radius: 8px; border: 1px solid #1a1a1a;">
            ${content}
          </div>
          <p style="margin-top: 20px; color: #9ca3af; font-size: 12px;">© 2026 NEXUS Technologies</p>
        </div>
      `,
        });

        if (error) {
            console.error('❌ Resend Error:', error);
            process.exit(1);
        }

        console.log('✅ Email sent successfully!', data);
    } catch (err) {
        console.error('❌ Unexpected Error:', err);
        process.exit(1);
    }
}

main();
