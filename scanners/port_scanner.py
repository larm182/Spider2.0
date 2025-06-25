import nmap
import socket
from datetime import datetime
import subprocess


class PortScanner:
    
    def scan_common_ports(self, target_host):
        print("\n--- Buscando Puertos ---")
        
        try:
            comando = f"sudo nmap -Pn -sV -p 1-10000 -O {target_host}"
            resultado_crudo = subprocess.check_output(comando, shell=True, text=True)
        except subprocess.CalledProcessError as e:
            return {
                "vulnerabilities": [
                    {
                        "type": "Error",
                        "severity": "Low",
                        "evidence": f"Fallo al ejecutar Nmap: {str(e)}"
                    }
                ]
            }

        datos_procesados = []
        sistema_operativo = None

        lines = resultado_crudo.splitlines()
        puerto_seccion = False

        for line in lines:
            # Detectar sección de puertos
            if line.startswith("PORT"):
                puerto_seccion = True
                continue

            # Procesar puertos
            if puerto_seccion and line.strip() and not line.startswith("Nmap done"):
                partes = line.split()
                if len(partes) >= 3:
                    puerto_estado = partes[0]   # 80/tcp
                    estado = partes[1]          # open
                    servicio = partes[2]        # http
                    version = " ".join(partes[3:]) if len(partes) > 3 else ""
                    datos_procesados.append({
                        "port": puerto_estado,
                        "state": estado,
                        "service": servicio,
                        "version": version
                    })

            # Detectar sistema operativo
            if line.startswith("OS details:"):
                sistema_operativo = line.replace("OS details:", "").strip()

        # Mostrar resultados por consola (opcional)
        print(f"{'-' * 50}")
        print(f"Host escaneado: {target_host}")
        print(f"Número de puertos detectados: {len(datos_procesados)}")
        if sistema_operativo:
            print(f"Sistema Operativo Detectado: {sistema_operativo}")
        print(f"{'-' * 50}")
        print(f"{'Puerto':<15}{'Estado':<15}{'Servicio':<20}{'Versión'}")
        print(f"{'-' * 50}")
        for r in datos_procesados:
            print(f"{r['port']:<15}{r['state']:<15}{r['service']:<20}{r['version']}")
        print(f"{'-' * 50}")

        # Formatear para frontend
        vulnerabilities = []

        for r in datos_procesados:
            if r["state"] == "open":
                evidence = f"Puerto {r['port']} abierto - Servicio: {r['service']}"
                if r["version"]:
                    evidence += f" ({r['version']})"
                vulnerabilities.append({
                    "type": "Puerto Abierto",
                    "severity": "Medium",
                    "evidence": evidence
                })

        if sistema_operativo:
            vulnerabilities.append({
                "type": "Sistema Operativo Detectado",
                "severity": "Info",
                "evidence": f"Nmap identificó el SO como: {sistema_operativo}"
            })

        if not vulnerabilities:
            vulnerabilities.append({
                "type": "Escaneo de Puertos",
                "severity": "Info",
                "evidence": "No se encontraron puertos abiertos en el rango escaneado."
            })

        return {
            "vulnerabilities": vulnerabilities
        }

