import requests
import re
from urllib.parse import urlparse, parse_qs, urljoin
from html.parser import HTMLParser
import urllib3
urllib3.disable_warnings()

SESSION_HEADERS = {
    "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36",
}


class FormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self._current_form = None
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._in_form = True
            action = attrs_dict.get("action", "")
            method = attrs_dict.get(
                "method", "get"
            ).upper()
            full_action = urljoin(
                self.base_url, action
            ) if action else self.base_url
            self._current_form = {
                "url":    full_action,
                "method": method,
                "params": [],
                "type":   "POST" if method == "POST"
                          else "GET",
            }
        elif tag in ("input", "textarea", "select") \
             and self._in_form and \
             self._current_form is not None:
            name = attrs_dict.get("name", "")
            input_type = attrs_dict.get("type", "text")
            if name and input_type not in (
                "submit", "reset", "button",
                "image", "file",
            ):
                self._current_form["params"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            if self._current_form and \
               self._current_form["params"]:
                self.forms.append(self._current_form)
            self._current_form = None
            self._in_form = False


class ParamExtractor:

    def extract(
        self,
        target_url: str,
        discovered_urls: list,
    ) -> dict:
        result = {
            "get_params":    [],
            "post_params":   [],
            "api_endpoints": [],
        }
        seen_urls = set()
        session = requests.Session()
        session.headers.update(SESSION_HEADERS)
        session.verify = False

        all_urls = list({target_url} |
                        set(discovered_urls[:60]))

        for url in all_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Extract GET params from URL
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for p in params.keys():
                        result["get_params"].append({
                            "url":   url,
                            "param": p,
                            "type":  "GET",
                        })
            except Exception:
                pass

            # Fetch page and extract forms
            try:
                resp = session.get(
                    url, timeout=8,
                    allow_redirects=True,
                )
                ct = resp.headers.get(
                    "content-type", ""
                ).lower()

                if "html" in ct:
                    parser = FormParser(url)
                    parser.feed(resp.text[:100000])
                    for form in parser.forms:
                        result["post_params"].append(
                            form
                        )

                if "json" in ct:
                    result["api_endpoints"].append({
                        "url":    url,
                        "method": "GET",
                    })
            except Exception:
                pass

        # Deduplicate get_params
        seen_get = set()
        deduped = []
        for p in result["get_params"]:
            key = f"{p['url']}:{p['param']}"
            if key not in seen_get:
                seen_get.add(key)
                deduped.append(p)
        result["get_params"] = deduped

        return result
