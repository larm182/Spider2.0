import requests


xss_wordlist = "wordlist/xss_wordlist.txt"
class XSSScanner:
    def scan_xss(self, target_url, deep_scan=False):
        print("\n--- Probando XSS ---")
        vulnerabilities = []

        try:
            with open(xss_wordlist, 'r') as file:
                for payload in file:
                    payload = payload.strip()
                    try:
                        response = requests.get(f"{target_url}{payload}", timeout=5)
                        if payload in response.text:
                            # Importante: escapar comillas y < > para HTML
                            payload_safe = payload.replace('"', '&quot;').replace("'", "&#39;").replace('<', '&lt;').replace('>', '&gt;')
                            vulnerabilities.append({
                                "type": "XSS",
                                "severity": "High",
                                "evidence": payload_safe
                            })
                    except:
                        continue
        except Exception as e:
            vulnerabilities.append({
                "type": "XSS",
                "severity": "Low",
                "evidence": f"Error: {str(e)}"
            })

        return {
            "vulnerabilities": vulnerabilities
        }


