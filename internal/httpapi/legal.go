package httpapi

import (
	"net/http"
	"strings"
)

// Google requires a homepage, privacy policy, and terms-of-service URL on an
// authorized domain before an OAuth app can be published. Serving them from
// authsvc itself keeps the disclosure next to the service it describes, and
// avoids a placeholder URL appearing on the consent screen real users see.
//
// The content below describes exactly what this service stores. If you change
// what is collected, change this too.

const legalCSS = `
:root{color-scheme:light dark}
body{font:16px/1.65 system-ui,-apple-system,sans-serif;max-width:44rem;
margin:8vh auto;padding:0 1.5rem}
h1{font-size:1.6rem;margin:0 0 .2rem}h2{font-size:1.05rem;margin:2rem 0 .4rem}
.sub{opacity:.6;margin:0 0 2rem;font-size:.9rem}
ul{padding-left:1.2rem}li{margin:.3rem 0}
code{background:rgba(127,127,127,.18);padding:.1rem .3rem;border-radius:.2rem;font-size:.9em}
a{color:#2563eb}footer{margin-top:3rem;font-size:.85rem;opacity:.6}
`

func legalPage(title, sub, body string) string {
	return `<!doctype html><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + title + ` · grindlog auth</title><style>` + legalCSS + `</style>` +
		`<h1>` + title + `</h1><p class="sub">` + sub + `</p>` + body +
		`<footer>grindlog auth · <a href="/">home</a> · <a href="/privacy">privacy</a> · <a href="/terms">terms</a></footer>`
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// Only the exact root; anything else stays a 404.
	if r.URL.Path != "/" {
		writeErr(w, http.StatusNotFound, "not_found", "no such endpoint")
		return
	}
	writeHTML(w, http.StatusOK, legalPage("grindlog auth",
		"Sign-in service for applications on "+hostOf(s.opts.Issuer)+".",
		`<p>This is an authentication service. It is not a product you sign up for
directly — you reach it when an application asks you to sign in, and it hands
you back to that application afterwards.</p>
<h2>What it does</h2>
<ul>
<li>Signs you in with an email and password, a one-time email code, Google, or GitHub.</li>
<li>Issues short-lived tokens the application uses to know who you are.</li>
<li>Lets you see and revoke your active sessions.</li>
</ul>
<h2>Links</h2>
<ul>
<li><a href="/privacy">Privacy policy</a></li>
<li><a href="/terms">Terms of service</a></li>
<li><a href="https://github.com/zb8ne/authsvc">Source code</a></li>
</ul>`))
}

func (s *Server) handlePrivacy(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, legalPage("Privacy policy",
		"What this service stores, and why.",
		`<h2>What is collected</h2>
<ul>
<li><strong>Your email address.</strong> Used to identify your account and to send
verification and password-reset messages.</li>
<li><strong>A password hash</strong>, if you set a password. The password itself is
never stored — only an <code>argon2id</code> hash of it.</li>
<li><strong>Provider account details</strong>, if you sign in with Google or GitHub: the
provider's stable account id, the email address they report, whether they say it
is verified, and your display name and avatar URL.</li>
<li><strong>Session records.</strong> One per sign-in and per token refresh, holding the
time, an expiry, your IP address, and your browser's user-agent string. These
exist so you can review and revoke your own sessions, and so a stolen token can
be detected and shut off.</li>
</ul>
<h2>What is not collected</h2>
<ul>
<li>No analytics, advertising, or tracking of any kind.</li>
<li>No payment details.</li>
<li>No contents of the applications you sign in to.</li>
</ul>
<h2>Who it is shared with</h2>
<p>Your email address is passed to the email provider (<a
href="https://resend.com/legal/privacy-policy">Resend</a>) solely to deliver
verification and reset messages. Data is stored on managed infrastructure
(<a href="https://railway.com/legal/privacy">Railway</a>). It is not sold, and
it is not shared with anyone else.</p>
<p>When you sign in with Google or GitHub, that provider learns you signed in
here. This service requests only your basic profile and email — nothing else.</p>
<h2>How long it is kept</h2>
<p>Account records are kept until the account is deleted. Expired sessions are
deleted automatically 30 days after they expire; one-time codes within a day.</p>
<h2>Your choices</h2>
<p>You can revoke individual sessions or sign out everywhere from the application
you signed in to. To have an account and its data deleted, contact the address
below.</p>
<h2>Contact</h2>
<p>`+s.opts.ContactEmail+`</p>`))
}

func (s *Server) handleTerms(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, http.StatusOK, legalPage("Terms of service",
		"The short version.",
		`<h2>What this is</h2>
<p>A sign-in service operated for applications on `+hostOf(s.opts.Issuer)+`. It is
provided free of charge and without warranty of any kind.</p>
<h2>Your responsibilities</h2>
<ul>
<li>Give accurate account details and keep your credentials to yourself.</li>
<li>Do not attempt to access accounts that are not yours, and do not attempt to
disrupt the service for others.</li>
<li>Do not use automated means to create accounts in bulk.</li>
</ul>
<h2>Availability</h2>
<p>There is no uptime guarantee. The service may change or stop at any time.
Accounts may be suspended if used for the things listed above.</p>
<h2>Liability</h2>
<p>To the extent permitted by law, the operator is not liable for any loss arising
from use of this service. It is offered as-is.</p>
<h2>Contact</h2>
<p>`+s.opts.ContactEmail+`</p>`))
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// hostOf strips the scheme and any leading auth. subdomain so the pages read as
// being about the parent domain.
func hostOf(issuer string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	h = strings.TrimSuffix(h, "/")
	return strings.TrimPrefix(h, "auth.")
}
