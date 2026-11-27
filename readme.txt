=== ForgeHub Honeypot Shield ===
Contributors: wpforgehub
Tags: antispam, honeypot, spam protection, comments, zero captcha
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Zero-CAPTCHA honeypot and HMAC time-trap spam shield for comments, registration, login, and forms with zero external APIs or server bloat.

== Description ==

**ForgeHub Honeypot Shield** stops automated spam bots silently—without annoying CAPTCHA puzzles, third-party tracking scripts, or monthly API fees.

Traditional CAPTCHAs hurt conversions, frustrate real visitors, and load heavy third-party JavaScript. ForgeHub Honeypot Shield combines an invisible CSS-hidden honeypot field with an HMAC-signed submission time-trap so automated bots get rejected at the door while humans pass through effortlessly.

### Key Features (Free Version)
* **Zero-CAPTCHA Invisible Honeypot**: Injects an accessible (`aria-hidden`, `tabindex="-1"`) hidden trap field that real visitors never see and automated bots fill automatically.
* **HMAC-Signed Time-Trap Protection**: Cryptographically signed timestamp rejects instant bot submissions (configurable minimum seconds) and expired replay tokens.
* **Complete Core Form Protection**: Protects Comments, User Registration, Login (`wp-login.php`), and Lost Password forms out of the box.
* **Flexible Comment Action**: Choose between immediate HTTP 403 rejection (zero database bloat) or marking caught comments as Spam.
* **Custom Honeypot Field Name**: Rename the trap field anytime while automatically blocking collisions with core form fields.
* **Local Blocked Spam Counter**: Track total blocked bots by surface directly in your dashboard with zero external telemetry.
* **100% Local & GDPR Friendly**: No external API calls, no cookies, no third-party scripts.

### Pro Features (Separate Commercial Plugin)
Need store and contact-form coverage, advanced rules, or audit logs? The separate commercial Pro edition is available at [WPForgeHub](https://wpforgehub.com/product/honeypot-shield/) and is not bundled in this free plugin:
* **WooCommerce Protection**: Honeypot & time-trap guard for WooCommerce Checkout and Customer Registration forms.
* **Contact Form 7 & WPForms Integration**: Automatic invisible protection for popular contact forms.
* **Advanced Spam Rules**: Max URLs per comment, custom keyword blacklist, disposable email domain blocker, and trusted IP allowlist.
* **Local Spam Activity Log & CSV Export**: Privacy-masked IP log of blocked attempts with configurable retention and one-click CSV export.

== Installation ==

1. Upload the `forgehub-honeypot-shield` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu.
3. Navigate to **Settings > Honeypot Shield** to review protected surfaces and adjust the minimum submit time.

== Frequently Asked Questions ==

= Does this plugin require a Google reCAPTCHA or Turnstile API key? =
No. ForgeHub Honeypot Shield works 100% locally with zero API keys, zero external requests, and zero CAPTCHA puzzles.

= Will it affect accessibility or screen readers? =
No. The honeypot container uses `aria-hidden="true"`, `tabindex="-1"`, and `autocomplete="off"` so assistive technologies and keyboard navigation skip it cleanly.

= Will it break XML-RPC, REST API, or programmatic logins? =
No. Login protection only inspects standard `wp-login.php` form submissions and leaves API/programmatic authentication untouched.

= Does it send visitor data to external servers? =
Never. All validation, counters, and optional Pro logs remain 100% inside your own database.

== Screenshots ==

1. Honeypot Shield settings panel showing live blocked-spam counters, protected surfaces, custom trap field name, and time-trap controls.

== Changelog ==

= 1.0.0 =
* Initial stable release with Zero-CAPTCHA honeypot, HMAC-signed time-trap, protection for Comments/Registration/Login/Lost Password, local stats counter, and Pro WooCommerce/CF7/WPForms integrations, advanced rules, and spam activity log.
