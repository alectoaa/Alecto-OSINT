import os
from pathlib import Path

class RawLeakEngine:
    def __init__(self, leaks_directory: str | Path | None = None):
        configured_directory = leaks_directory or os.getenv(
            "RAW_LEAKS_DIRECTORY",
            str(Path(__file__).parent / "data" / "dumps"),
        )
        self.leaks_dir = Path(configured_directory).expanduser()

    def search_credential(self, query):
        """
        Yerel dizindeki tüm .txt/.csv dump dosyalarında ham arama yapar.
        Query: Email veya Username
        """
        results = []
        if not self.leaks_dir.exists():
            return results

        # Belirtilen dizindeki tüm dosyaları tara
        for file_path in self.leaks_dir.iterdir():
            if file_path.suffix.lower() in (".txt", ".csv", ".sql"):
                try:
                    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            # Eğer satır aranan kelimeyi (örn: email) içeriyorsa
                            if query.lower() in line.lower():
                                clean_line = line.strip()
                                # İsteğe bağlı: email:password formatını doğrula
                                results.append({
                                    "source_file": file_path.name,
                                    "raw_data": clean_line # Ham veri ve parola burada görünür
                                })
                                # Performans için dosya başına sonuç limitlenebilir
                                if len(results) >= 50:
                                    break
                except OSError:
                    continue
        
        return results