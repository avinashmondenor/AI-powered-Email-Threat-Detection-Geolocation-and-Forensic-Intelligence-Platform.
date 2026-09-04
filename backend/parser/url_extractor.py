import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
from typing import List, Dict, Any

URL_REGEX = re.compile(
    r'http[s]?://(?:[a-zA-Z0-9$-_@.&+!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
)

def extract_urls(text_body: str, html_body: str) -> List[Dict[str, Any]]:
    extracted = []
    seen_urls = set()

    def add_url(url: str, source: str, anchor_text: str = ""):
        clean_url = url.strip().rstrip(".,;)'\"")
        if not clean_url or clean_url in seen_urls:
            return
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            return
        seen_urls.add(clean_url)

        parsed = urlparse(clean_url)
        ext = tldextract.extract(clean_url)
        domain = ext.registered_domain or parsed.netloc

        extracted.append({
            "url": clean_url,
            "scheme": parsed.scheme,
            "domain": domain,
            "hostname": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "source": source,
            "anchor_text": anchor_text.strip()
        })

    # Extract from plain text body
    if text_body:
        matches = URL_REGEX.findall(text_body)
        for u in matches:
            add_url(u, "text_body")

    # Extract from HTML body
    if html_body:
        soup = BeautifulSoup(html_body, 'html.parser')
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            anchor_text = tag.get_text()
            add_url(href, "html_anchor", anchor_text)
        
        # Also check img src
        for img in soup.find_all('img', src=True):
            src = img['src']
            add_url(src, "html_image")

    return extracted
