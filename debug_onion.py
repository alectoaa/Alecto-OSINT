"""

"""
import asyncio, aiohttp, os
from aiohttp_socks import ProxyConnector

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"}

SITES = [
    ("Riseup Paste",      "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion/"),
    ("Stronghold Paste",  "http://strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion/"),
    ("IntelligenceX",     "http://4p6mwq6iy37xhq4s.onion/"),
    ("DeepPaste",         "http://depastedihrn3jtw.onion/"),
    ("GhostBin",          "http://ghostbinmake7blo.onion/"),
    ("Onion Leaks",       "http://leakqjwv2mwpnpbc.onion/"),
    ("Hidden Wiki v3",    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/"),
    ("Dark.fail onion",   "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/"),
    ("Excavator",         "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query=test"),
    ("Torch",             "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query=test&action=search"),
    ("OnionLand",         "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q=test"),
    ("NotEvil",           "http://hss3uro2hsxfogfq.onion/?q=test"),
    ("Candle",            "http://gjobqjj7wyczbqie.onion/?q=test"),
    ("Phobos",            "http://phobosxilamwcg75xt22id7wga34k76x7s7u7l6j3ijz7orfzbbfh6ad.onion/search?query=test"),
    ("Onion Search v2",   "http://kn3hl4xwon63tc6hpjrwza2npb7d4w5cem3m7332r4gv7cjz6zeebqd.onion/?q=test"),
]

async def main():
    proxy_url = os.getenv("TOR_PROXY", "socks5://127.0.0.1:9050")
    for name, url in SITES:
        connector = ProxyConnector.from_url(proxy_url)
        try:
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=20), headers=HEADERS) as r:
                    text = await r.text(errors="ignore")
                    print(f"OK  [{name}] HTTP={r.status} size={len(text)}", flush=True)
        except Exception as e:
            print(f"ERR [{name}] {type(e).__name__}: {str(e)[:60]}", flush=True)
        finally:
            if not connector.closed:
                await connector.close()
        await asyncio.sleep(0.5)

asyncio.run(main())
print("DONE", flush=True)
