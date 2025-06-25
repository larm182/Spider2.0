import requests
from datetime import datetime

lfi_wordlist = "wordlist/LFI_wordlist.txt"

class LFIScanner:
    def scan_lfi(self, target_url, deep_scan=False):
    
        print("\n--- Probando Local File Inclusión ---")
        vulnerable = []
        results = {
            "target": target_url,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": [],
            "errors": []
        }
        with open(lfi_wordlist, 'r') as file:
            for payload in file:
                payload = payload.strip()
                try:
                    test_url = f"{target_url}{payload}"
                    response = requests.get(test_url, timeout=5)
                    if payload in response.text:
                        print(f"[VULNERABLE] LFI detectado en {test_url}")
                        results["vulnerabilities"].append({
                            "type": "Local File Inclusion",
                            "severity": "High",
                            "payload": payload,
                            "url": test_url,
                            "evidence": f"LFI detectado con payload: {payload} en {test_url}"
                        })
                except Exception as e:
                    results["errors"].append(str(e))
        return results

    def to_frontend_format(self, raw_result):
        formatted = {
            "vulnerabilities": []
        }

        for vuln in raw_result.get("vulnerabilities", []):
            formatted["vulnerabilities"].append({
                "type": vuln.get("type", "Local File Inclusion"),
                "severity": vuln.get("severity", "Medium"),
                "payload": vuln.get("payload", ""),
                "url": vuln.get("url", ""),
                "parameter": vuln.get("parameter", ""),  # opcional
                "method": vuln.get("method", "GET"),     # puedes ajustar esto
                "evidence": vuln.get("evidence", "Sin evidencia")
            })

        return formatted


                        
        
    

