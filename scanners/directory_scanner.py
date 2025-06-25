import requests

wordlist_ = "wordlist/directory_wordlist.txt"

class DirectoryScanner:
    def scan_directories(self, target_url, deep_scan=False):
        print("\n--- Buscando directorios ---")
        vulnerabilities = []

        try:
            with open(wordlist_, 'r') as file:
                for line in file:
                    directory = line.strip()
                    full_url = f"{target_url.rstrip('/')}/{directory}"

                    try:
                        response = requests.get(full_url, timeout=5)
                        if response.status_code == 200:
                            print(f"[ENCONTRADO] {full_url}")
                            vulnerabilities.append({
                                "type": "Directorio Accesible",
                                "severity": "Medium",
                                "evidence": full_url
                            })
                    except requests.RequestException:
                        continue
        except Exception as e:
            vulnerabilities.append({
                "type": "Error",
                "severity": "Low",
                "evidence": f"No se pudo leer el wordlist: {e}"
            })

        return {
            "vulnerabilities": vulnerabilities
        }
