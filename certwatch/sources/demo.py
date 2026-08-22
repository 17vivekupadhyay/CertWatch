"""Synthetic CT stream for offline demo mode.

Produces normalized certificate records at a realistic, slightly irregular rate.
The mix is mostly-boring legitimate traffic with planted attacks at roughly
1-in-200, and deliberate *near-misses* that should NOT fire so the demo also
shows precision. Seed it for a reproducible run.

Records match the shape the scorer expects::

    {"seen_at", "not_before", "issuer", "domains", "log", "is_precert"}
"""

import random
import time
import itertools

# A slice of genuinely popular domains — the boring background traffic.
TOP_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "reddit.com", "instagram.com", "linkedin.com", "netflix.com", "microsoft.com",
    "apple.com", "twitter.com", "office.com", "bing.com", "twitch.tv",
    "github.com", "stackoverflow.com", "medium.com", "wordpress.com", "shopify.com",
    "cloudflare.com", "adobe.com", "salesforce.com", "zoom.us", "dropbox.com",
    "spotify.com", "paypal.com", "ebay.com", "nytimes.com", "bbc.co.uk",
    "theguardian.com", "cnn.com", "espn.com", "imdb.com", "yelp.com",
    "booking.com", "airbnb.com", "uber.com", "doordash.com", "walmart.com",
    "target.com", "bestbuy.com", "homedepot.com", "costco.com", "etsy.com",
    "canva.com", "notion.so", "figma.com", "slack.com", "atlassian.com",
    "gitlab.com", "bitbucket.org", "digitalocean.com", "heroku.com", "vercel.app",
    "netlify.app", "stripe.com", "squareup.com", "quickbooks.com", "mailchimp.com",
    "hubspot.com", "zendesk.com", "intercom.com", "asana.com", "trello.com",
    "coursera.org", "udemy.com", "khanacademy.org", "duolingo.com", "wikipedia.org",
    "nih.gov", "nasa.gov", "weather.com", "accuweather.com", "healthline.com",
    "mayoclinic.org", "webmd.com", "indeed.com", "glassdoor.com", "monster.com",
]

# Word banks for procedurally generating plausible boring domains.
_ADJ = ["north", "blue", "green", "swift", "bright", "prime", "urban", "coastal",
        "summit", "cedar", "maple", "silver", "golden", "rapid", "clear", "solid",
        "modern", "united", "central", "atlas", "vertex", "nova", "apex", "delta"]
_NOUN = ["supplies", "logistics", "systems", "labs", "works", "studio", "group",
         "partners", "capital", "media", "digital", "consulting", "solutions",
         "ventures", "networks", "designs", "builders", "traders", "foods",
         "clinic", "dental", "realty", "fitness", "brewing", "roasters", "outfitters"]
_TLD_LEGIT = ["com", "com", "com", "com", "net", "org", "io", "co", "us",
              "co.uk", "de", "ca", "com.au"]
_SUBS = ["www", "app", "mail", "shop", "blog", "api", "cdn", "static", "portal",
         "dashboard", "help", "docs", "status", "m"]

_ISSUERS = ["Let's Encrypt", "Let's Encrypt", "Let's Encrypt", "Google Trust Services",
            "DigiCert Inc", "Sectigo Limited", "GoDaddy.com, Inc.", "ZeroSSL",
            "Amazon", "Cloudflare Inc ECC CA-3"]
_FREE_ISSUERS = ["Let's Encrypt", "Google Trust Services", "ZeroSSL", "Cloudflare Inc ECC CA-3"]

_LOGS = ["google_argon2026h2", "google_xenon2026h2", "cloudflare_nimbus2026",
         "sectigo_sabre2026", "digicert_yeti2026"]

# Attack recipes. Each returns a list of SAN domains + an issuer hint.
_BRAND_SQUATS = {
    "paypal": ["paypal", "paypa1", "paypaI", "paypai", "paypall", "paypal-secure",
               "secure-paypal", "paypal-account"],
    "microsoft": ["micros0ft", "rnicrosoft", "microsoft", "microsoft0nline",
                  "office365", "0ffice365", "micosoft"],
    "apple": ["appie", "app1e", "apple-id", "appleid", "apple-icloud", "icloud-apple"],
    "amazon": ["amazon", "amaz0n", "arnazon", "amazon-security", "amazonn"],
    "google": ["g00gle", "goog1e", "gooogle", "google-account", "gmai1"],
    "coinbase": ["coinbase", "coinbase-wallet", "c0inbase", "coinbasе"],  # last has cyrillic e
    "netflix": ["netfIix", "netfllx", "netflix-billing", "netf1ix"],
    "chase": ["chase-secure", "chasse", "chase-verify", "chaseonline-secure"],
    "meta": ["faceb00k", "facebook-login", "instagrarn", "1nstagram", "whatsapp-web"],
    "okta": ["okta-sso", "0kta", "okta-login"],
    "dhl": ["dhl-express", "dhl-tracking", "dh1"],
}

_KEYWORDS = ["login", "signin", "secure", "verify", "account", "update", "confirm",
             "billing", "invoice", "support", "recover", "unlock", "auth", "sso"]

_ABUSE_TLDS = ["top", "xyz", "click", "tk", "cf", "gq", "ml", "sbs", "cam", "quest", "zip"]

# Synthetic hosting locations for demo-mode enrichment (offline demo has no DNS,
# so we plant plausible geo on a fraction of attacks to populate the map while
# leaving the rest "staged"). Countries that commonly host abuse infra.
_DEMO_GEO = [
    ("United States", "US", "Ashburn", 39.04, -77.49, "Cloudflare", "AS13335"),
    ("United States", "US", "Buffalo", 42.88, -78.87, "ColoCrossing", "AS36352"),
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90, "M247", "AS9009"),
    ("Russia", "RU", "Moscow", 55.75, 37.62, "Selectel", "AS49505"),
    ("Germany", "DE", "Frankfurt", 50.11, 8.68, "Hetzner", "AS24940"),
    ("Singapore", "SG", "Singapore", 1.35, 103.82, "DigitalOcean", "AS14061"),
    ("China", "CN", "Hangzhou", 30.29, 120.16, "Alibaba", "AS37963"),
    ("Vietnam", "VN", "Hanoi", 21.03, 105.85, "VNPT", "AS45899"),
    ("Brazil", "BR", "Sao Paulo", -23.55, -46.63, "Locaweb", "AS27715"),
    ("India", "IN", "Mumbai", 19.08, 72.88, "OVH", "AS16276"),
    ("Nigeria", "NG", "Lagos", 6.52, 3.38, "MainOne", "AS37282"),
    ("Turkey", "TR", "Istanbul", 41.01, 28.98, "Natro", "AS207990"),
]

# Near-misses: real-looking domains that mention a brand-ish word or use an
# abuse TLD but should score low. These prove precision.
_NEAR_MISSES = [
    ["applesupplies.com"], ["mynetflixreview.blog"], ["applyingnow.com"],
    ["securepay-invoices.io"], ["metadata-labs.com"], ["chaselodge.co.uk"],
    ["appletonclinic.com"], ["identity-design.studio"], ["oktaylor.com"],
    ["support.mycompany.com"], ["blog.acmecorp.xyz"], ["thegoogleplex-fanpage.net"],
    ["visahq-travel.com"], ["metaphor-media.com"], ["amazonianplants.com"],
]


# Subdomain templates for discovery-mode demo traffic. A mix of sensitive hosts
# (which should fire) and ordinary public ones (which should stay routine), so
# the discovery panel demonstrates precision the same way the phishing feed does.
_ASSET_SUBS = [
    "grafana.staging", "jenkins.dev", "vault.internal", "kibana.prod",
    "gitlab.corp", "argocd.k8s", "prometheus.internal", "clickhouse-dev.aws",
    "postgres.staging", "redis.internal", "admin.uat", "vpn.corp",
    "backup.db", "phpmyadmin.dev", "sonarqube.ci", "nexus.build",
    "elastic.logging", "rabbitmq.internal", "api-internal.staging", "sso.corp",
    # ordinary public hosts — should read as routine, not alarming
    "www", "cdn", "static.assets", "mail", "docs", "status", "shop",
    "blog", "support", "api", "app", "portal",
]


class DemoGenerator:
    def __init__(self, seed=None, rate=25.0, owned_domains=None):
        self.rng = random.Random(seed)
        self.rate = max(0.5, rate)
        self._counter = itertools.count(1)
        self.owned_domains = list(owned_domains or [])

    # -- building blocks --------------------------------------------------
    def _legit_domain(self):
        if self.rng.random() < 0.45:
            base = self.rng.choice(TOP_DOMAINS)
        else:
            base = f"{self.rng.choice(_ADJ)}{self.rng.choice(_NOUN)}.{self.rng.choice(_TLD_LEGIT)}"
        if self.rng.random() < 0.6:
            sub = self.rng.choice(_SUBS)
            return f"{sub}.{base}"
        return base

    def _legit_record(self):
        n = 1
        r = self.rng.random()
        if r < 0.15:
            n = self.rng.randint(2, 4)
        elif r < 0.02:
            n = self.rng.randint(20, 60)  # legit SAN-heavy cert (hosting)
        domains = []
        base = self._legit_domain()
        domains.append(base)
        for _ in range(n - 1):
            domains.append(self._legit_domain())
        if self.rng.random() < 0.3:
            # add the apex + www pair
            apex = base.split(".", 1)[-1] if base.count(".") > 1 else base
            domains = [apex, f"www.{apex}"]
        return self._record(domains, self.rng.choice(_ISSUERS))

    def _attack_record(self):
        brand = self.rng.choice(list(_BRAND_SQUATS))
        variant = self.rng.choice(_BRAND_SQUATS[brand])
        style = self.rng.random()
        tld = self.rng.choice(_ABUSE_TLDS + ["com", "com", "net", "co"])
        kw = self.rng.choice(_KEYWORDS)

        if style < 0.30:
            # lookalike registrable domain, maybe with keyword hyphenated
            label = variant if self.rng.random() < 0.5 else f"{variant}-{kw}"
            domain = f"{label}.{tld}"
        elif style < 0.55:
            # brand in subdomain of an unrelated registrable
            noun = self.rng.choice(_NOUN)
            domain = f"{brand}.{kw}-{noun}.{tld}"
        elif style < 0.72:
            # keyword + brand hyphenated registrable
            domain = f"{kw}-{brand}-{self.rng.choice(['secure','online','center'])}.{tld}"
        elif style < 0.85:
            # punycode homoglyph
            puny = {
                "paypal": "xn--pypal-4ve", "apple": "xn--pple-43d",
                "microsoft": "xn--microsft-q9a", "google": "xn--googl-fsa",
                "amazon": "xn--amazn-mye", "coinbase": "xn--conbase-o0a",
            }.get(brand, "xn--pypal-4ve")
            domain = f"{puny}.{tld}"
        else:
            # DGA-like label with an abuse TLD
            chars = "abcdefghijklmnpqrstvwxyz0123456789"
            label = "".join(self.rng.choice(chars) for _ in range(self.rng.randint(9, 14)))
            domain = f"{label}.{self.rng.choice(_ABUSE_TLDS)}"

        domains = [domain]
        if self.rng.random() < 0.5:
            domains.append("www." + domain)
        issuer = self.rng.choice(_FREE_ISSUERS)  # attacks overwhelmingly free DV
        rec = self._record(domains, issuer)
        rec["_demo_enrich"] = self._synth_enrich()
        return rec

    def _synth_enrich(self):
        # ~55% of staged campaigns already have a live host; the rest are still
        # being set up (cert exists, no A record yet) — the compelling case.
        if self.rng.random() < 0.45:
            return {"resolves": False, "ips": [], "ip": None, "geo": None}
        c = self.rng.choice(_DEMO_GEO)
        octet = lambda: self.rng.randint(1, 254)
        ip = f"{octet()}.{octet()}.{octet()}.{octet()}"
        return {
            "resolves": True, "ips": [ip], "ip": ip,
            "geo": {"ip": ip, "country": c[0], "countryCode": c[1], "city": c[2],
                    "lat": c[3] + self.rng.uniform(-0.3, 0.3),
                    "lon": c[4] + self.rng.uniform(-0.3, 0.3),
                    "isp": c[5], "org": c[5], "asn": c[6]},
        }

    def _near_miss_record(self):
        domains = list(self.rng.choice(_NEAR_MISSES))
        return self._record(domains, self.rng.choice(_ISSUERS))

    def _asset_record(self):
        """A cert for a subdomain of one of the owned domains (discovery mode)."""
        owned = self.rng.choice(self.owned_domains)
        sub = self.rng.choice(_ASSET_SUBS)
        domain = f"{sub}.{owned}"
        domains = [domain]
        if self.rng.random() < 0.25:
            domains = [f"*.{sub.split('.')[-1]}.{owned}", domain]
        rec = self._record(domains, self.rng.choice(_FREE_ISSUERS))
        rec["_demo_enrich"] = self._synth_enrich()
        return rec

    def _record(self, domains, issuer):
        now = time.time()
        # cert issued a few seconds to a couple minutes ago
        age = self.rng.random() * 120
        return {
            "seen_at": now,
            "not_before": now - age,
            "issuer": issuer,
            "domains": domains,
            "log": self.rng.choice(_LOGS),
            "is_precert": self.rng.random() < 0.5,
            "_demo_seq": next(self._counter),
        }

    # -- public API -------------------------------------------------------
    def next_record(self):
        r = self.rng.random()
        if r < 1 / 200:
            return self._attack_record()
        # When discovery mode is on, plant owned-subdomain certs at ~1/50 so the
        # discovery panel populates at a watchable rate.
        if self.owned_domains and r < 1 / 200 + 1 / 50:
            return self._asset_record()
        if r < 1 / 200 + 1 / 50 + 1 / 60:
            return self._near_miss_record()
        return self._legit_record()

    def stream(self, sleep=True):
        """Yield records forever at roughly ``self.rate`` per second with jitter."""
        while True:
            yield self.next_record()
            if sleep:
                # irregular inter-arrival: exponential around the mean rate
                delay = self.rng.expovariate(self.rate)
                time.sleep(min(delay, 0.5))


def _main():
    import sys
    import json
    seed = None
    rate = 25.0
    args = sys.argv[1:]
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1])
    if "--rate" in args:
        rate = float(args[args.index("--rate") + 1])
    gen = DemoGenerator(seed=seed, rate=rate)
    try:
        for rec in gen.stream(sleep=True):
            rec = dict(rec)
            rec.pop("_demo_seq", None)
            rec.pop("_demo_enrich", None)
            sys.stdout.write(json.dumps(rec) + "\n")
            sys.stdout.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    _main()
