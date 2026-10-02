import asyncio
from dotenv import load_dotenv
load_dotenv()
from intelligence.breach_engine import BreachEngine

async def test():
    results = await BreachEngine().search("adobe@mailinator.com", "EMAIL")
    print(f"Toplam: {len(results)} sonuc")
    for item in results:
        src     = item["source"]
        snippet = item["snippet"][:70]
        print(f"  [{src:20s}] {snippet}")

asyncio.run(test())
