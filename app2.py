from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os
from datetime import datetime
#from report_generator import ReportGenerator
from scanners.port_scanner import PortScanner
from scanners.xss_scanner import XSSScanner
from scanners.directory_scanner import DirectoryScanner
from scanners.header_analyzer import HeaderAnalyzer
from scanners.sql_injection_scanner import SQLInjectionScanner
from scanners.tech_detector import TechDetector
from scanners.secret_scanner import SecretScanner
from scanners.lfi_scanner import LFIScanner
from scanners.brute_force import BruteForce
from scanners.command_injection_scanner import CommandInjectionScanner
from report_generator import ReportGenerator


app = Flask(__name__)
CORS(app)  # Permitir CORS para todas las rutas

# Configuración
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'reports'

port_scanner = PortScanner()
xss_scanner = XSSScanner()
directory_scanner = DirectoryScanner()
header_analyzer = HeaderAnalyzer()
sqli_scanner = SQLInjectionScanner()
tech_detector = TechDetector()
secret_scanner = SecretScanner()
lfi_scanner = LFIScanner()
brute_force = BruteForce()
cmdi_scanner = CommandInjectionScanner()

# Initialize report generator
report_generator = ReportGenerator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')
    scan_types = request.form.getlist('scan_types')

    if not target_url:
        return jsonify({'error': 'URL objetivo requerida'}), 400
    
    if not scan_types:
        return jsonify({'error': 'Debe seleccionar al menos un tipo de escaneo'}), 400

     # Initialize results
    results = {
        'target': target_url,
        'scan_time': datetime.now().isoformat(),
        'scan_types': scan_types,
        'status': 'success'
    }

    print(results)
    
    try:
        # Execute selected scans
        for scan_type in scan_types:
            if scan_type == 'ports':
                results['port_scan'] = port_scanner.scan_common_ports(target_url)
            elif scan_type == 'directories':
                results['directory_scan'] = directory_scanner.scan_directories(target_url)
            elif scan_type == 'secrets':
            	raw_result = secret_scanner.scan_secrets(target_url)
            	unique = {}
            	for s in raw_result.get('secrets_found', []):

            		key = (s['type'], s['match'], s['url'])
            		if key not in unique:
            			unique[key] = s
            	raw_result['secrets_found'] = list(unique.values())
            	results['secrets_scan'] = secret_scanner.to_frontend_format(raw_result)
			    
            elif scan_type == 'xss':
                results['xss_scan'] = xss_scanner.scan_xss(target_url)
            elif scan_type == 'sqli':            	#
            	raw_result = sqli_scanner.scan_sql_injection(target_url)            	
            	results['sqli_scan'] = sqli_scanner.to_frontend_format(raw_result)
            	
            elif scan_type == 'cmdi':
            	raw_result = cmdi_scanner.scan_command_injection(target_url)
            	#print("[DEBUG] Resultados Command Injection:", raw_result)
            	results["cmdi_scan"] = {
			        "vulnerabilities": [
			            {
			                "type": vuln.get("type", "Command Injection"),
			                "severity": vuln.get("severity", "High"),
			                "evidence": f"""Método: {vuln.get("method", "")}
				Parámetro: {vuln.get("parameter", "")}
				Payload: {vuln.get("payload", "")}
				Sistema: {vuln.get("os_type", "desconocido")}
				Método de detección: {vuln.get("detection_method", "")}

				Evidencia:
				{vuln.get("evidence", "")}
				""",
				                "payload": vuln.get("payload", ""),
				                "url": vuln.get("url", ""),
				                "parameter": vuln.get("parameter", ""),
				                "method": vuln.get("method", ""),
				            }
				            for vuln in raw_result.get("vulnerabilities", [])
				        ]
				    }
            	results["target"] = target_url
            	results["scan_types"] = ["cmdi"]
            	results["status"] = "success"
            elif scan_type == 'lfi':
            	vulnerable_payloads = lfi_scanner.scan_lfi(target_url)
            	#print("[DEBUG] Payloads vulnerables LFI:", vulnerable_payloads)
            	from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
            	vulnerabilities = []
            	for payload in vulnerable_payloads:
            		parsed = urlparse(target_url)
            		qs = parse_qs(parsed.query)
            		qs['file'] = [payload]
            		new_query = urlencode(qs, doseq=True)
            		vuln_url = urlunparse((
			            parsed.scheme,
			            parsed.netloc,
			            parsed.path,
			            parsed.params,
			            new_query,
			            parsed.fragment
	        		))

            		vulnerabilities.append({
			            "type": "Local File Inclusion",
			            "severity": "High",
			            "payload": payload,
			            "url": vuln_url,
			            "parameter": "file",
			            "method": "GET",
			            "evidence": f"LFI detectado con payload: {payload} en {vuln_url}"
			        })


            	raw_result_dict = {
			         "target": target_url,
			        "scan_time": datetime.now().isoformat(),
			        "vulnerabilities": vulnerabilities,
			        "errors": []
    			}

            	results["lfi_scan"] = lfi_scanner.to_frontend_format(vulnerable_payloads)
            	results["target"] = target_url
            	results["scan_types"] = ["lfi"]
            	results["status"] = "success"

            elif scan_type == 'headers':
                results['header_scan'] = header_analyzer.analyze_headers(target_url)
                raw_result = header_analyzer.analyze_headers(target_url)
                results['header_scan'] = header_analyzer.to_frontend_format(raw_result)
            elif scan_type == 'tech':
            	raw_result = tech_detector.detect_technologies(target_url)
            	results['tech_scan'] = tech_detector.to_frontend_format(raw_result)
            	
            	print(">>> JSON final enviado al frontend:", results)
            elif scan_type == 'brute':

            	raw_result = brute_force.scan_brute_force(target_url)
            	#print("[DEBUG] Resultados Brute Force:", raw_result)
            	formatted = {"vulnerabilities": [] }
            	for cred in raw_result.get("successful_logins", []):
            		formatted["vulnerabilities"].append({
            			"type": "Fuerza Bruta",
			            "severity": "High",
			            "url": cred.get("form_url", cred.get("endpoint", target_url)),
			            "method": cred.get("method", "POST"),
			            "parameter": "username/password",
			            "payload": f'{cred["username"]}:{cred["password"]}',
			            "evidence": cred.get("evidence", "Login exitoso")
			        })
            	results["brute_scan"] = brute_force.to_frontend_format(raw_result)
            	results["target"] = target_url
            	results["scan_types"] = ["brute"]
            	results["status"] = "success"
                
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            'error': f'Error durante el escaneo: {str(e)}',
            'target': target_url,
            'status': 'error'
        }), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Genera un reporte PDF a partir de los resultados del escaneo."""
    try:
        scan_results = request.get_json()

        if not scan_results:
            return jsonify({'error': 'No se proporcionaron resultados de escaneo'}), 400

        target_url = scan_results.get('target', 'Unknown')
        
        # Inicializar generador de reportes si aún no está
        global report_generator
        if not report_generator:
            report_generator = ReportGenerator()

        # Generar reporte
        report_path = report_generator.generate_comprehensive_report(scan_results, target_url)

        return send_file(
            report_path,
            as_attachment=True,
            download_name=os.path.basename(report_path),
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({'error': f'Error generando reporte: {str(e)}'}), 500


if __name__ == '__main__':
    # Crear directorio de reportes si no existe
    os.makedirs('reports', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)