# LitSpace — Digital eBook Marketplace

A responsive, light-first (with persistent dark mode) digital bookstore built with HTML, CSS, JavaScript, Node.js, Express and SQLite. Includes animated 3D-style book covers, categories and novel genres, NGN/USD pricing, customer accounts, a private admin inventory studio, PDF uploads, free titles, secure purchased downloads, and payment checkout integrations.

## Quick start

1. Install **Node.js 20+**.
2. In this folder run `npm install`.
3. Copy `.env.example` to `.env`. Replace `JWT_SECRET` with a random secret (32+ characters), and set `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters).
4. Run `npm run dev` and open **http://localhost:3000**.
5. Sign in with the admin email/password you configured. Click **Admin studio** to upload PDFs, add covers, edit titles and pricing, make books free, or unpublish books.
6. Sample listings are **fictional placeholders** and have no downloadable PDFs. Upload a PDF you are legally entitled to distribute before offering a title for sale. Do not use sample book listings as real inventory.

## Payment providers

The site supports four checkout integrations, but **none is live until configured**. Configure only providers available to your registered business and settlement jurisdiction. Merchant eligibility and supported currencies vary.

- **Paystack** (NGN): Set `PAYSTACK_SECRET_KEY`. In the Paystack dashboard configure the webhook URL `https://YOUR-DOMAIN/api/webhooks/paystack`. Supports payment channels enabled for your merchant (such as cards, transfers, or USSD). Transaction amount is verified server-side.
- **Stripe** (NGN/USD where supported): Set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`. Register `https://YOUR-DOMAIN/api/webhooks/stripe` for `checkout.session.completed`. Stripe account availability depends on merchant country; do not assume a Nigerian Stripe account can be opened directly.
- **PayPal** (USD): Set `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET` and `PAYPAL_ENV=sandbox` (or `live`). Merchant receiving eligibility varies by country. Checkout is captured and verified server-side.
- **Flutterwave** (NGN/USD where enabled): Set `FLW_SECRET_KEY`. Hosted checkout redirects to LitSpace, which verifies transaction ID, reference, currency, amount and status on the server.

**Important:** A bank transfer option is available through Paystack/Flutterwave only when enabled by the merchant and checkout provider. This app does **not** manually credit orders based on customer claims or screenshots. For production, add Flutterwave webhooks and persistent return-order identifiers, as well as reconciliation for delayed payments. Stripe is webhook-confirmed; Paystack is webhook-confirmed or verified on return; PayPal and Flutterwave are verified on return. Do not go live without testing all flows, refunds and failed payments.

## Currency handling

Prices are independently entered by the admin in NGN and USD, **not converted using a live exchange rate**. The admin can set a price for each currency. Both values are stored in minor units (kobo/cents) to avoid floating-point payment errors. A price of zero in either currency without the Free toggle will block checkout in that currency. Setting Free makes both prices zero and allows signed-in customers to download the PDF.

## Security and production checklist

- Use HTTPS, a strong random JWT secret, secure cookies, strong admin credentials, and production environment variables.
- Run behind a reverse proxy, configure a trusted domain and correct `BASE_URL`.
- Configure email verification, password resets, stricter login rate limiting, and bot protections.
- Add server-side MIME/magic-byte validation, malware scanning, file access logging, upload quotas, and optional PDF watermarking.
- Set up encrypted backups for `private/litspace.sqlite` and `uploads/`.
- Review tax/VAT, Nigerian data protection obligations, refund policies, copyright licensing, privacy policy and terms of service.
- Implement production-grade observability, failed-payment reconciliation, and provider webhooks for all enabled methods.
- Ensure you have **digital resale/distribution rights** for books purchased from other vendors. Buying an ordinary consumer eBook does not automatically give permission to resell or redistribute it.
- For large-scale use, move files to private object storage, use Postgres, and add a proper transactional inventory/entitlement layer.

## What works immediately without merchant keys

- Homepage, categories, search, genres, responsive UI, animated 3D book showcase
- Light mode by default and saved dark-mode preference
- Account registration and login; admin bootstrap
- Add/edit/unpublish books, upload/replace covers and PDF files
- Set free books, NGN and USD prices
- Signed-in library and permission-checked PDF downloads

## What needs external configuration or further hardening

- Real payment processing requires approved merchant accounts, live API keys, and webhooks.
- Customer email delivery, online in-browser reading, ratings, cart, discount codes, analytics and automatic multi-vendor ingestion are not implemented in this MVP.
- The app is a **functional local MVP / starter project**, not a fully audited production commerce system.
