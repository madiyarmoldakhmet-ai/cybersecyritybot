# 🚀 Aegis Production Deployment Guide

This guide will help you deploy the Aegis Full-Stack Web Platform to production using Vercel (for the Next.js Frontend) and Railway / Render (for the FastAPI Backend and Telegram Bot).

## Prerequisites
- A GitHub account with the `cybersecuritybot` repository pushed.
- A Vercel account (https://vercel.com).
- A Railway (https://railway.app) or Render (https://render.com) account.
- A Telegram Bot Token from [@BotFather](https://t.me/BotFather).

---

## Step 1: Deploy Backend & Bot (Railway)

1. Go to your Railway dashboard and click **New Project** -> **Deploy from GitHub repo**.
2. Select your `cybersecuritybot` repository.
3. Railway will automatically detect the `railway.json` file we created and the `Dockerfile.server`, and will begin building the Python backend environment.
4. **Configure Environment Variables:**
   Go to the Variables tab in Railway and add the following:
   - `TELEGRAM_BOT_TOKEN`: (Your bot token from BotFather)
   - `LLM_PROVIDER`: `openrouter` (or your preferred LLM provider)
   - `OPENROUTER_API_KEY`: (Your API key)
   - `PORT`: `8000` (Railway often provides this dynamically, but it's good to specify if needed).
5. **Generate Domain:**
   Go to the Settings tab -> Networking -> click **Generate Domain**.
   *Note this domain down (e.g., `https://aegis-backend-production.up.railway.app`). This is your `BACKEND_URL`.*

---

## Step 2: Deploy Frontend (Vercel)

1. Go to your Vercel dashboard and click **Add New** -> **Project**.
2. Import your `cybersecuritybot` repository.
3. **Important: Root Directory Configuration:**
   In the "Root Directory" section, click **Edit** and select the `aegis_web` folder.
4. **Configure Environment Variables:**
   Open the Environment Variables section and add:
   - Name: `NEXT_PUBLIC_WS_URL`
   - Value: `wss://<YOUR_BACKEND_DOMAIN_WITHOUT_HTTPS>/ws/scan`
     *(Example: `wss://aegis-backend-production.up.railway.app/ws/scan`)*
5. Click **Deploy**.
6. Once deployed, note down your frontend domain (e.g., `https://aegis-web.vercel.app`). This is your `FRONTEND_URL`.

---

## Step 3: Link Environments (CORS & Bot Config)

Now that both services are up, we need to let the backend know about the frontend.

1. Go back to your **Railway Dashboard**.
2. In the Variables tab, add the following variables:
   - `FRONTEND_URL`: Your Vercel frontend URL (e.g., `https://aegis-web.vercel.app`). This allows CORS so the frontend can connect to the WebSocket.
   - `WEB_APP_URL`: Your Vercel frontend URL (e.g., `https://aegis-web.vercel.app`). This tells the Telegram bot which URL to open when users click the Launch button.
3. Railway will automatically trigger a redeploy with the new environment variables. Wait for it to finish.

---

## Step 4: Configure Telegram Bot Settings

1. Open Telegram and message **@BotFather**.
2. Send `/mybots` and select your Aegis bot.
3. Go to **Bot Settings** -> **Menu Button** -> **Configure menu button**.
4. Send the URL of your Vercel frontend (e.g., `https://aegis-web.vercel.app`).
5. Send a short title like `Launch Aegis`.
6. Now, whenever someone opens your bot, they will see a persistent "Launch Aegis" button next to the text input!

## Verification
- Message your Telegram bot `/start`. It should reply with a welcome message and an inline button "Launch Aegis Dashboard".
- Click the button. The Telegram Web App (your Vercel site) should pop up.
- Paste a GitHub repository URL into the scanner and hit "Launch Scan".
- You should see the Terminal streaming logs and the Metrics updating in real-time, all powered by your Railway backend!
