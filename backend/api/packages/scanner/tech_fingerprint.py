import requests
import re
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings()

TECH_SIGNATURES = {
    "headers": {
        "server": {
            "nginx":      "Nginx",
            "apache":     "Apache",
            "iis":        "Microsoft IIS",
            "cloudflare": "Cloudflare CDN",
            "vercel":     "Vercel",
            "netlify":    "Netlify",
            "lighttpd":   "Lighttpd",
            "caddy":      "Caddy",
            "gunicorn":   "Gunicorn",
            "uvicorn":    "Uvicorn",
        },
        "x-powered-by": {
            "php":        "PHP",
            "asp.net":    "ASP.NET",
            "express":    "Express.js",
            "django":     "Django",
            "rails":      "Ruby on Rails",
            "laravel":    "Laravel",
            "next.js":    "Next.js",
        },
        "x-generator": {
            "wordpress":  "WordPress",
            "drupal":     "Drupal",
            "joomla":     "Joomla",
        },
        "via": {
            "cloudfront": "AWS CloudFront",
            "varnish":    "Varnish Cache",
            "squid":      "Squid Proxy",
        },
    },
    "cookies": {
        "PHPSESSID":           "PHP",
        "JSESSIONID":          "Java / Tomcat",
        "ASP.NET_SessionId":   "ASP.NET",
        "laravel_session":     "Laravel",
        "django":              "Django",
        "wp-":                 "WordPress",
        "rack.session":        "Ruby on Rails",
        "connect.sid":         "Node.js Express",
    },
    "html_patterns": {
        "wp-content":          "WordPress",
        "wp-includes":         "WordPress",
        "Drupal.settings":     "Drupal",
        "joomla":              "Joomla",
        "__NEXT_DATA__":       "Next.js",
        "_nuxt":               "Nuxt.js",
        "ng-version":          "Angular",
        "react":               "React.js",
        "data-reactroot":      "React.js",
        "__gatsby":            "Gatsby",
        "Shopify.theme":       "Shopify",
        "woocommerce":         "WooCommerce",
        "magento":             "Magento",
        "bootstrap":           "Bootstrap CSS",
        "tailwindcss":         "Tailwind CSS",
        "cloudflare":          "Cloudflare",
    },
}

WAF_SIGNATURES = {
    "cloudflare":   ["cf-ray", "cloudflare", "__cfduid"],
    "aws_waf":      ["x-amzn-requestid", "x-amz-cf-id"],
    "akamai":       ["akamai", "x-akamai-transformed"],
    "sucuri":       ["x-sucuri-id", "sucuri"],
    "incapsula":    ["incap_ses", "visid_incap"],
    "mod_security": ["mod_security", "modsecurity"],
    "barracuda":    ["barra_counter_session"],
}


class TechFingerprintService:

    def detect(self, target_url: str) -> dict:
        result = {
            "technologies": [], # Will now store [{"name": "...", "version": "..."}]
            "server":        None,
            "powered_by":    None,
            "cdn_detected":  False,
            "waf_detected":  False,
            "waf_name":      None,
            "raw_headers":   {},
            "cookies_found": [],
        }

        try:
            resp = requests.get(
                target_url,
                timeout=12,
                verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent":
                        "Mozilla/5.0 (compatible; "
                        "ShieldSentinel/1.0)",
                },
            )
        except Exception as e:
            result["error"] = str(e)
            return result

        headers = {
            k.lower(): v.lower()
            for k, v in resp.headers.items()
        }
        body = resp.text[:50000].lower()
        cookies = [c.lower()
                   for c in resp.cookies.keys()]

        result["raw_headers"] = dict(
            list(resp.headers.items())[:25]
        )
        
        # Helper to extract version using regex
        def extract_version(text):
            if not text: return None
            # Common version patterns like /1.2.3 or v1.2.3 or -1.2.3
            match = re.search(r"/(?:v)?(\d+(?:\.\d+)+)", text)
            if not match:
                # Fallback for just space then number
                match = re.search(r"\s(?:v)?(\d+(?:\.\d+)+)", text)
            return match.group(1) if match else None

        result["server"] = resp.headers.get("Server")
        result["powered_by"] = resp.headers.get("X-Powered-By")

        tech_map = {} # name -> version

        # Header-based
        for hdr, patterns in TECH_SIGNATURES["headers"].items():
            val_raw = resp.headers.get(hdr, "")
            val_lower = val_raw.lower()
            
            for keyword, name in patterns.items():
                if keyword in val_lower:
                    version = extract_version(val_raw)
                    if not version and name == "WordPress":
                        # Special check for WP meta tag version if header fails
                        wp_v = re.search(r'content="wordpress (\d+(?:\.\d+)+)"', body)
                        if wp_v: version = wp_v.group(1)
                    
                    tech_map[name] = version or tech_map.get(name)

        # Cookie-based
        for cookie_key, name in TECH_SIGNATURES["cookies"].items():
            if any(cookie_key.lower() in c for c in cookies):
                tech_map[name] = tech_map.get(name)
                result["cookies_found"].append(cookie_key)

        # HTML body
        for pattern, name in TECH_SIGNATURES["html_patterns"].items():
            if pattern.lower() in body:
                tech_map[name] = tech_map.get(name)

        # TLS / HTTPS detection
        if target_url.startswith("https://"):
            tech_map["HTTPS / TLS"] = None

        # CDN detection
        cdn_headers = ["cf-ray", "x-amz-cf-id", "x-cdn", "via"]
        cdn_values = ["cloudflare", "cloudfront", "akamai", "fastly", "varnish", "cdn"]
        for h in cdn_headers:
            val = headers.get(h, "")
            if any(c in val for c in cdn_values):
                result["cdn_detected"] = True
                break

        # WAF detection
        all_header_text = " ".join(f"{k}:{v}" for k, v in headers.items())
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s in all_header_text for s in sigs):
                result["waf_detected"] = True
                result["waf_name"] = waf_name
                break

        # Convert tech_map to list of objects
        result["technologies"] = [
            {"name": name, "version": version}
            for name, version in tech_map.items()
        ]
        result["technologies"].sort(key=lambda x: x["name"])
        
        return result
