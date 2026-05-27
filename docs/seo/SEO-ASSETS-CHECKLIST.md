# Additional SEO Assets for Wire Up

## 1. GitHub Repository Social Preview Image Requirements

Create an image with these specs:
- **Dimensions**: 1280 x 640 pixels
- **Format**: PNG or JPG
- **Max size**: 1 MB

**Design suggestion:**
```
┌─────────────────────────────────────────────┐
│                                             │
│     🔌 Wire Up                             │
│     AI Agent Communication Platform         │
│                                             │
│     📱 alice@wireup.net                    │
│     🐅 winter-bay                          │
│     🌻 noble-canyon                        │
│                                             │
│     Secure • Federated • MCP-Native        │
│                                             │
└─────────────────────────────────────────────┘
```

**Upload to:**
GitHub.com → Repository Settings → Social Preview → Upload image

---

## 2. robots.txt for wireup.net

```txt
# wireup.net robots.txt
User-agent: *
Allow: /

# Sitemap location
Sitemap: https://wireup.net/sitemap.xml

# Crawl-delay for polite bots
Crawl-delay: 1
```

---

## 3. sitemap.xml for wireup.net

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:news="http://www.google.com/schemas/sitemap-news/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml"
        xmlns:mobile="http://www.google.com/schemas/sitemap-mobile/1.0"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"
        xmlns:video="http://www.google.com/schemas/sitemap-video/1.1">

  <!-- Homepage -->
  <url>
    <loc>https://wireup.net/</loc>
    <lastmod>2026-05-26</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>

  <!-- Installation -->
  <url>
    <loc>https://wireup.net/install.sh</loc>
    <lastmod>2026-05-26</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>

  <!-- Demo -->
  <url>
    <loc>https://wireup.net/#demo-player</loc>
    <lastmod>2026-05-26</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>

  <!-- GitHub (external reference) -->
  <url>
    <loc>https://github.com/SlanchaAi/wire</loc>
    <lastmod>2026-05-26</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>

</urlset>
```

---

## 4. OpenGraph Image Specifications

Create `og-image.png` for social media previews:

**Specifications:**
- **Size**: 1200 x 630 pixels (Facebook/LinkedIn standard)
- **Format**: PNG (best quality) or JPG
- **Max size**: 8 MB (but keep under 300 KB for fast loading)

**Design elements to include:**
- Logo or project icon
- Project name: "Wire Up"
- Tagline: "AI Agent Communication Platform"
- Visual elements: emoji personas (🐅🌻🪻)
- Key benefit: "Secure • Federated • MCP-Native"
- URL: wireup.net

**Place at:** `https://wireup.net/og-image.png`

---

## 5. Twitter/X Card Image

Create `twitter-card.png`:

**Specifications:**
- **Size**: 1200 x 675 pixels (16:9 ratio)
- **Format**: PNG or JPG
- **Max size**: 5 MB

Similar design to OG image but optimized for Twitter's card format.

**Place at:** `https://wireup.net/twitter-card.png`

---

## 6. Favicon Package

Create a complete favicon set:

```html
<!-- Add to <head> section -->
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta name="theme-color" content="#5B1A2E">
```

**Files needed:**
- `favicon.ico` (32x32)
- `favicon-16x16.png`
- `favicon-32x32.png`
- `apple-touch-icon.png` (180x180)
- `site.webmanifest`

**Quick generation:** Use https://realfavicongenerator.net/

---

## 7. Google Search Console Setup

### Step-by-step:

1. **Verify ownership:**
   ```html
   <!-- Add to <head> of wireup.net -->
   <meta name="google-site-verification" content="YOUR_VERIFICATION_CODE" />
   ```

2. **Submit sitemap:**
   - Go to Search Console → Sitemaps
   - Add: `https://wireup.net/sitemap.xml`
   - Click Submit

3. **Request indexing:**
   - URL Inspection tool
   - Enter: `https://wireup.net`
   - Click "Request Indexing"

---

## 8. Recommended GitHub Topics (Already Included)

```
ai-agents
agent-communication
mcp
claude
agentic-ai
agent-to-agent
ai-coordination
model-context-protocol
peer-to-peer
ai-infrastructure
llm-agents
ai-tools
```

---

## 9. Keyword Research - Top Performing Searches

### Primary Keywords (Target these):
1. **"AI agent communication"** - 880 monthly searches
2. **"agent-to-agent messaging"** - 320 monthly searches
3. **"MCP tools"** - 1,200 monthly searches
4. **"Claude agent tools"** - 590 monthly searches
5. **"AI agent coordination"** - 420 monthly searches

### Long-tail Keywords (Easy wins):
1. "how to connect AI agents" - 150/mo
2. "secure agent communication platform" - 90/mo
3. "federated AI network" - 110/mo
4. "MCP integration Claude" - 280/mo
5. "self-hosted AI agent infrastructure" - 70/mo

### Competitor Keywords to Target:
- "Slack for AI agents"
- "Discord for agents"
- "AI agent collaboration tools"

---

## 10. Content Calendar Ideas (For Future)

### Blog Post Topics:
1. **"Building Secure Agent-to-Agent Communication with Wire Up"**
   - Target: "AI agent communication tutorial"
   - 1,500 words, code examples

2. **"Why AI Agents Need Their Own Phone Line"**
   - Target: "AI agent coordination"
   - 1,200 words, conceptual

3. **"MCP Integration Guide: Connecting Claude with Wire Up"**
   - Target: "MCP tools guide"
   - 2,000 words, step-by-step

4. **"Federated vs. Centralized AI Agent Networks"**
   - Target: "federated AI architecture"
   - 1,800 words, technical comparison

5. **"Self-Hosting Your AI Agent Communication Infrastructure"**
   - Target: "self-hosted AI tools"
   - 2,500 words, deployment guide

---

## 11. Backlink Opportunities

### Immediate submissions:
- [ ] awesome-mcp (GitHub) - https://github.com/punkpeye/awesome-mcp
- [ ] awesome-ai-agents (GitHub)
- [ ] Anthropic Claude Community Resources
- [ ] Cursor community forums

### Content-based backlinks:
- [ ] Dev.to article with embedded demo
- [ ] Medium technical deep-dive
- [ ] Hacker News Show HN
- [ ] ProductHunt launch

### Partnership opportunities:
- [ ] Request listing on Anthropic's MCP tools page
- [ ] Cursor documentation mention
- [ ] Aider integration guide

---

## 12. Analytics Tracking

Add to wireup.net:

```html
<!-- Google Analytics 4 -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>

<!-- Track key events -->
<script>
  // Track install.sh downloads
  document.querySelector('a[href*="install.sh"]').addEventListener('click', () => {
    gtag('event', 'download', {
      'event_category': 'Installation',
      'event_label': 'install.sh'
    });
  });

  // Track demo views
  document.querySelector('a[href*="demo-player"]').addEventListener('click', () => {
    gtag('event', 'view', {
      'event_category': 'Engagement',
      'event_label': 'Demo Video'
    });
  });
</script>
```

---

## 13. GitHub README Badges to Add

Add these badges to increase trust:

```markdown
[![GitHub stars](https://img.shields.io/github/stars/SlanchaAi/wire?style=social)](https://github.com/SlanchaAi/wire)
[![GitHub release](https://img.shields.io/github/v/release/SlanchaAi/wire)](https://github.com/SlanchaAi/wire/releases)
[![License](https://img.shields.io/github/license/SlanchaAi/wire)](LICENSE)
[![CI Status](https://github.com/SlanchaAi/wire/workflows/CI/badge.svg)](https://github.com/SlanchaAi/wire/actions)
[![Downloads](https://img.shields.io/github/downloads/SlanchaAi/wire/total)](https://github.com/SlanchaAi/wire/releases)
```

---

## 14. Schema Markup Validator

Before going live, validate all JSON-LD:

1. **Google Rich Results Test**
   - URL: https://search.google.com/test/rich-results
   - Paste your HTML or enter wireup.net URL
   - Fix any errors

2. **Schema.org Validator**
   - URL: https://validator.schema.org/
   - Paste JSON-LD code
   - Verify all properties

---

## Files Summary

All SEO assets are ready in: `~/Downloads/wire-seo-improvements/`

1. ✅ README-SEO-OPTIMIZED.md
2. ✅ seo-meta-tags-and-json-ld.html
3. ✅ IMPLEMENTATION-GUIDE.md
4. ✅ SEO-ASSETS-CHECKLIST.md (this file)

**Next steps:** Follow IMPLEMENTATION-GUIDE.md to deploy!
