"""Recon mode: map a target's attack surface from Certificate Transparency.

The moment any host gets a certificate, its name is published to a permanent
public log — so ``grafana.staging.target.com`` or ``vault.internal.target.com``
becomes visible the instant the cert issues, even if the host is firewalled and
unlinked. The *name alone* leaks environment (dev/staging), tooling (Grafana,
Jenkins, ClickHouse), auth entry points (VPN, SSO, OWA), and topology.

This is passive subdomain enumeration and attack-surface mapping — the same
public-OSINT technique used by ``amass``, ``subfinder`` and ``crt.sh``. Point it
at a set of target domains and it surfaces their subdomains as certs appear,
ranked by recon value (credentials > internal/admin > entry points > infra >
non-prod > routine).

AUTHORIZATION: use only against targets you are authorized to assess — your own
assets, published bug-bounty scope, or an engagement with written permission.
CertWatch is strictly passive: it reads public logs and does a DNS lookup for
enrichment. It never connects to, scans, or probes the discovered hosts.

Runs as a second scorer over the same ingest/parse/dedupe pipeline as the
phishing detector, keyed on a target watchlist instead of a brand watchlist.
"""

import json
import os
import threading

from .brands import registrable, split_domain

# ---------------------------------------------------------------------------
# Risk taxonomy. Each label maps to (points, tag). A subdomain is scanned for
# these tokens across its dot/hyphen-delimited labels; points accumulate.
# ``tech`` tokens additionally record which technology the name reveals.
# ---------------------------------------------------------------------------

# Non-production environments — usually less hardened than prod.
ENV_TOKENS = {
    "dev": "non-production", "develop": "non-production", "development": "non-production",
    "staging": "non-production", "stage": "non-production", "stg": "non-production",
    "uat": "non-production", "qa": "non-production", "test": "non-production",
    "testing": "non-production", "sandbox": "non-production", "sbx": "non-production",
    "preprod": "non-production", "pre": "non-production", "demo": "non-production",
    "beta": "non-production", "canary": "non-production", "int": "non-production",
}

# Internal / administrative — should almost never be internet-facing.
INTERNAL_TOKENS = {
    "internal": "internal/admin", "intranet": "internal/admin", "corp": "internal/admin",
    "private": "internal/admin", "priv": "internal/admin", "admin": "internal/admin",
    "adminpanel": "internal/admin", "backoffice": "internal/admin", "vpn": "internal/admin",
    "ldap": "internal/admin", "ad": "internal/admin", "cpanel": "internal/admin",
    "whm": "internal/admin", "phpmyadmin": "internal/admin", "adminer": "internal/admin",
    "pgadmin": "internal/admin", "webmail": "internal/admin", "owa": "internal/admin",
}

# Secrets / sensitive data stores — highest sensitivity.
SECRET_TOKENS = {
    "vault": "secrets/keys", "secret": "secrets/keys", "secrets": "secrets/keys",
    "kms": "secrets/keys", "keys": "secrets/keys", "backup": "backup/dumps",
    "backups": "backup/dumps", "dump": "backup/dumps", "dumps": "backup/dumps",
}

# Infra / tooling — leaks the tech stack and is often unauthenticated by default.
TECH_TOKENS = {
    "jenkins": "Jenkins", "gitlab": "GitLab", "bitbucket": "Bitbucket", "git": "Git",
    "grafana": "Grafana", "kibana": "Kibana", "prometheus": "Prometheus",
    "alertmanager": "Alertmanager", "consul": "Consul", "nomad": "Nomad",
    "argocd": "Argo CD", "argo": "Argo", "rancher": "Rancher", "k8s": "Kubernetes",
    "kubernetes": "Kubernetes", "nexus": "Nexus", "artifactory": "Artifactory",
    "sonar": "SonarQube", "sonarqube": "SonarQube", "jira": "Jira",
    "confluence": "Confluence", "splunk": "Splunk", "elastic": "Elasticsearch",
    "elasticsearch": "Elasticsearch", "logstash": "Logstash", "rabbitmq": "RabbitMQ",
    "kafka": "Kafka", "redis": "Redis", "memcached": "Memcached",
    "postgres": "PostgreSQL", "postgresql": "PostgreSQL", "mysql": "MySQL",
    "mariadb": "MariaDB", "mongo": "MongoDB", "mongodb": "MongoDB",
    "clickhouse": "ClickHouse", "cassandra": "Cassandra", "db": "database",
    "database": "database", "grpc": "gRPC",
}

# Authentication / entry points — the first thing an attacker probes, because
# they're internet-facing by design and a way in if creds leak or MFA is weak.
ENTRYPOINT_TOKENS = {
    "login": "entry point", "signin": "entry point", "sso": "entry point",
    "auth": "entry point", "oauth": "entry point", "oidc": "entry point",
    "idp": "entry point", "vpn": "entry point", "portal": "entry point",
    "remote": "entry point", "rdp": "entry point", "citrix": "entry point",
    "owa": "entry point", "webmail": "entry point", "extranet": "entry point",
    "gateway": "entry point", "gw": "entry point", "access": "entry point",
}

# Named services worth listing but not alarming on their own.
SERVICE_TOKENS = {
    "api": "service", "dashboard": "service", "app": "service",
    "ftp": "service", "sftp": "service", "ssh": "service", "grpc": "service",
}

# Ordinary public hosts — routine, no points.
PUBLIC_TOKENS = {
    "www", "cdn", "static", "assets", "img", "images", "media", "m", "mobile",
    "shop", "store", "blog", "docs", "help", "support", "status", "mail", "mx",
    "smtp", "autodiscover", "email",
}

DISCOVERY_BANDS = ((60, "critical"), (40, "high"), (20, "medium"), (0, "routine"))


def discovery_severity(score):
    for t, name in DISCOVERY_BANDS:
        if score >= t:
            return name
    return "routine"


def _labels(subdomain):
    parts = []
    for chunk in subdomain.lower().replace(".", "-").split("-"):
        if chunk:
            parts.append(chunk)
    return parts


class AssetWatch:
    """Ownership watchlist: the registrable domains you're monitoring. Hot-reloads
    when the file changes on disk, like the brand watchlist."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = 0.0
        self.domains = set()
        self.load()

    def load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        owned = set()
        # Accept "targets" (recon framing) or "domains" (asset framing).
        for d in (data.get("targets", []) + data.get("domains", [])):
            d = d.strip().lower()
            if not d:
                continue
            r = registrable(d) or d
            owned.add(r)
        with self._lock:
            self.domains = owned
            try:
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                self._mtime = 0.0

    def maybe_reload(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return False
        if mtime > self._mtime:
            try:
                self.load()
                return True
            except (json.JSONDecodeError, OSError):
                return False
        return False

    def owns(self, reg_domain):
        with self._lock:
            return reg_domain.lower() in self.domains

    def all_domains(self):
        with self._lock:
            return set(self.domains)


class DiscoveryScorer:
    def __init__(self, assetwatch):
        self.assets = assetwatch

    def _score_subdomain(self, sub):
        labels = _labels(sub)
        tags, tech = [], []
        points = 0
        for lab in labels:
            if lab in SECRET_TOKENS:
                points += 45
                _add(tags, SECRET_TOKENS[lab])
            elif lab in INTERNAL_TOKENS:
                points += 40
                _add(tags, INTERNAL_TOKENS[lab])
            elif lab in TECH_TOKENS:
                points += 35
                _add(tags, "infra/tooling")
                _add(tech, TECH_TOKENS[lab])
            elif lab in ENV_TOKENS:
                points += 30
                _add(tags, ENV_TOKENS[lab])
            elif lab in ENTRYPOINT_TOKENS:
                points += 25
                _add(tags, "entry point")
            elif lab in SERVICE_TOKENS:
                points += 12
                _add(tags, "named service")
        score = min(100, points)
        return score, tags, tech

    def score_cert(self, record):
        """Return a list of asset findings for domains under an owned registrable
        domain. Empty if the cert has nothing we own."""
        findings = []
        seen = set()
        for raw in record.get("domains", []):
            dom = raw.lower().strip().lstrip(".")
            is_wild = dom.startswith("*.")
            if is_wild:
                dom = dom[2:]
            reg = registrable(dom)
            if not reg or not self.assets.owns(reg):
                continue
            sub, _main, _suf = split_domain(dom)
            # Skip the apex and the plain public www — not interesting as assets.
            if sub in ("", "www"):
                continue
            key = dom
            if key in seen:
                continue
            seen.add(key)
            score, tags, tech = self._score_subdomain(sub)
            findings.append({
                "domain": dom,
                "registrable": reg,
                "owned_domain": reg,
                "subdomain": sub,
                "score": score,
                "severity": discovery_severity(score),
                "tags": tags,
                "tech": tech,
                "is_wildcard": is_wild,
                "issuer": record.get("issuer", ""),
                "log": record.get("log", ""),
                "is_precert": record.get("is_precert", False),
                "not_before": record.get("not_before"),
                "seen_at": record.get("seen_at"),
            })
        findings.sort(key=lambda f: f["score"], reverse=True)
        return findings


def _add(lst, val):
    if val not in lst:
        lst.append(val)
