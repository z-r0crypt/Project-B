# Project-B

# Ethical Recon Framework — Passive & Active Skeleton (python)

## Recon Modes

### 1. Passive Recon
> **Definition here:** “Passive” means *no intrusive interaction with target-owned systems*. Sources include public datasets, search engines, CT logs, threat intel, and internet-wide scanners’ existing data. (Some teams also allow low-impact HTTP GETs; if you prefer *true passive only*, we can toggle those off.)

- **Fast Mode** (broad, shallow, low-cost)
  - Quick subdomain gathering
    - Certificate Transparency (crt.sh), BufferOver passive DNS
    - Search engine dorking (site:, inurl:, filetype:) for hostnames
  - Basic domain context
    - WHOIS snapshot (registrar, creation/expiry), RDAP
    - CT SAN harvesting for base/wildcard pivots
  - Lightweight DNS overview
    - A/AAAA, NS, MX, TXT (SPF/DMARC policy presence only), CNAME
    - Basic IP → ASN & geo lookup
  - Rapid web tech hints (optional *low-impact* GET)
    - Favicon hashing → technology/CDN hints (hash-to-tech db)
    - HSTS presence (via headers seen in caches/archives where possible)

- **Thorough Mode** (deep, correlated, ASM-grade)
  - **Domain & DNS Intelligence**
    - Expanded subdomain enumeration: VirusTotal, SecurityTrails, Amass/Subfinder (passive sources), analytics/ad IDs (GA/GTAG/GTM, FB Pixel) pivots
    - DNS record analysis: MX/TXT/SPF/DKIM/DMARC, NS/SOA, CNAME chains, glue/TTL oddities
    - DNSSEC posture: DS records present/missing, algorithm/rollover issues (from public resolvers/data)
    - WHOIS & *historical* WHOIS, RDAP events; registrar/registry lock signals
    - Reverse WHOIS to discover sibling domains; corporate entity & email pivots
    - Domain & brand monitoring: IDN homograph look-alikes, confusables, permutation/typosquat sets, **newly registered** and zone-add monitoring
    - HSTS preload list monitoring & misalignment (preloaded vs headers)
  
  - **Infrastructure & IP Intelligence**
    - ASN discovery, owned/net-new IP blocks (IPv4/IPv6), PeeringDB relationships, IXPs
    - BGP posture & **RPKI validation status** of announced prefixes (signed/invalid/unknown)
    - Internet-wide scanners (enrichment only): Shodan, Censys, ZoomEye, FOFA — ports/services, device types, tags (e.g., Grafana/Prometheus, Kubernetes API)
    - Reverse IP & hosting graph: shared infra, co-hosted assets, PTR/rdns pivots
    - CDN/WAF identification (Akamai/Cloudflare/Fastly/etc.), **edge mapping** by POP hostnames in CT/WAF headers (from third-party data)
    - Cloud discovery
      - Provider IP ranges & service banners observed by scanners
      - Publicly named storage & endpoints: S3/GCS/Azure Blob (names from CT, JS, docs, repos, dorks)
      - Cert reuse clustering across hosts → infer internal services or shared certs
  
  - **Code & Configuration Exposure**
    - Public code search: GitHub/GitLab/Bitbucket orgs, users, forks; query by company, domain, email, ASN, GA IDs
    - Commit history & issues/PRs review (tokens, endpoints, secrets in diffs & discussions)
    - Secret patterns: cloud keys, JWTs, OAuth creds, DSNs (Sentry/Bugsnag), access tokens, private URLs
    - Public paste sites (Pastebin, Ghostbin, pastes on GitHub gists)
    - Public container registries (Docker Hub, GHCR): images, tags, **layer strings** & config leaks (ENV, CMD hints)
    - Package ecosystems: npm/PyPI/RubyGems/Go modules under org scope; leaked config in `package.json`, README, test fixtures
    - Exposed files via dorks: `.env`, `.conf`, `.xml`, `.log`, `.sql`, `.bak`, `.swp` (only if indexed/cached)
    - IaC & CI/CD artifacts: Terraform, CloudFormation, GitHub Actions logs/artifacts (public), Jenkins console outputs (indexed)
  
  - **Leaked Credentials & Data**
    - Breach corpus checks: HIBP, commercial breach providers (as metadata only; no credential handling)
    - Dark web & underground mentions: company/brand, executives, domains, VPN/SSO, “RDP/VPN access” listings
    - Public documents & metadata: PDF/DOCX/XLSX scraped by search engines — creator usernames, paths, software versions, internal hostnames in metadata
    - Token hunting in public assets: API keys in JS/source maps discovered via Wayback & indexed caches
  
  - **Web & Application Intelligence**
    - Technology stack triangulation: headers observed by scanners/caches, favicon hashes, third-party services (BuiltWith/Wappalyzer datasets)
    - Website archives (Wayback) for historical JS, robots.txt, sitemap.xml; discover gone-but-linked endpoints
    - API discovery: public Swagger/OpenAPI, Postman **public workspaces/collections**, GraphQL endpoints referenced in docs
    - PWA & frontend artifacts: `manifest.json`, service worker names, source map references (from archives/caches)
    - Mobile app OSINT (store-only):
      - App Store / Play Store listings → endpoints in screenshots/descriptions, support URLs, privacy policy domains
      - Team/Developer org names for pivoting; version history, SDKs from store metadata
      - Public crash dashboards referenced in docs (Sentry/Crashlytics project slugs)
  
  - **SaaS & Third‑Party Surface**
    - Org presence & exposure on: Atlassian (Jira/Confluence cloud), Slack/Discord invite links, Zendesk/ServiceNow portals, Notion, Airtable, Miro, Figma
    - Public dashboards: Grafana/Prometheus/Kibana/Datadog/New Relic with public view flags (as seen via search engines/scanners)
    - Postman, Stoplight, SwaggerHub orgs; GitBook/Readme.io docs; Statuspage.io incidents & component names
    - SSO tenant discovery (Okta/AzureAD/Google) via public org pages, TXT records, job posts
  
  - **Human & Brand Intelligence (OSINT)**
    - Employee footprint: LinkedIn/Twitter(X)/GitHub; email format enumeration; exposed personal sites linking corp assets
    - Org intelligence: job postings → stacks, partner names, internal system names; public filings; vendor lists
    - Brand impersonation: phishing domains, fake social accounts, **fake mobile apps**; **IDN/Unicode confusables** watchlist
    - RSS/Atom feeds & newsroom monitoring to spot newly announced subdomains/apps
  
  - **Cross‑Cutting Capabilities (Passive Data Pipeline)**
    - Normalization & deduplication: asset graph (domain ↔ host ↔ IP ↔ cert ↔ repo ↔ SaaS)
    - Change detection: CT deltas, new DNS answers, new repo leaks, new SaaS exposures, new typosquats
    - Confidence scoring: source reputation, recency, corroboration count
    - Prioritization hints: sensitive tech (admin panels, CI/CD, file shares), exposed management ports (from scanners’ data)
    - Legal/ethics guardrails: scope enforcement, rate limiting to third‑party APIs, no handling/display of plaintext credentials

### 2. Active Recon
- **Fast Mode**
  - Lightweight HTTP fingerprinting (status, headers, title)
  - Banner grabbing for top 10 ports

- **Thorough Mode**
  - Full HTTP fingerprinting with tech stack hints
  - Service detection (TCP/UDP common ports)
  - Screenshot capture
  - JavaScript file enumeration & endpoint extraction
  - Form and input field enumeration (potential XSS/SQLi points)
  - Directory and file brute-forcing (common wordlists)
  - Virtual host enumeration
  - SSL/TLS configuration analysis

---

## Example Usage
```bash
# Fast Passive Recon
tool.py recon --mode passive --speed fast --targets example.com

# Thorough Active Recon
tool.py recon --mode active --speed thorough --targets example.com
```

---

## Next Steps
- Implement **Passive Recon core** (fast + thorough) modules
- Build **Active Recon core** (fast + thorough) modules
- Add **AI-assisted prioritization** for findings
- Ensure scope enforcement for all modules

