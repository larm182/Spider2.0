import requests
from datetime import datetime
import re

class HeaderAnalyzer:
    def __init__(self):
        # Headers de seguridad importantes
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Fuerza conexiones HTTPS',
                'risk_level': 'medium',
                'recommendation': 'Implementar HSTS para prevenir ataques de downgrade'
            },
            'Content-Security-Policy': {
                'description': 'Previene ataques XSS y de inyección de código',
                'risk_level': 'high',
                'recommendation': 'Implementar CSP para controlar recursos cargados'
            },
            'X-Frame-Options': {
                'description': 'Previene ataques de clickjacking',
                'risk_level': 'medium',
                'recommendation': 'Configurar para prevenir embedding en frames'
            },
            'X-Content-Type-Options': {
                'description': 'Previene MIME type sniffing',
                'risk_level': 'low',
                'recommendation': 'Establecer en "nosniff" para prevenir ataques MIME'
            },
            'X-XSS-Protection': {
                'description': 'Protección XSS del navegador',
                'risk_level': 'low',
                'recommendation': 'Activar protección XSS del navegador'
            },
            'Referrer-Policy': {
                'description': 'Controla información de referrer',
                'risk_level': 'low',
                'recommendation': 'Configurar política de referrer apropiada'
            },
            'Permissions-Policy': {
                'description': 'Controla características del navegador',
                'risk_level': 'low',
                'recommendation': 'Configurar permisos de características del navegador'
            }
        }
        
        # Headers que pueden revelar información sensible
        self.information_disclosure_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via'
        ]
    
    def analyze_headers(self, target_url):
        """
        Analiza los headers HTTP del sitio objetivo
        """
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'headers': {},
            'security_analysis': {
                'present_security_headers': [],
                'missing_security_headers': [],
                'information_disclosure': [],
                'security_score': 0,
                'recommendations': []
            },
            'cookie_analysis': [],
            'errors': []
        }
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            # Realizar petición HTTP
            response = requests.get(
                target_url,
                timeout=15,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                allow_redirects=True
            )
            
            # Almacenar todos los headers
            results['headers'] = dict(response.headers)
            
            # Analizar headers de seguridad
            self._analyze_security_headers(response.headers, results)
            
            # Analizar divulgación de información
            self._analyze_information_disclosure(response.headers, results)
            
            # Analizar cookies
            self._analyze_cookies(response.headers, results)
            
            # Calcular puntuación de seguridad
            self._calculate_security_score(results)
            
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo al sitio: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado: {str(e)}")
        
        return results
    
    def _analyze_security_headers(self, headers, results):
        """
        Analiza la presencia de headers de seguridad
        """
        for header_name, header_info in self.security_headers.items():
            if header_name in headers:
                header_analysis = {
                    'name': header_name,
                    'value': headers[header_name],
                    'description': header_info['description'],
                    'risk_level': header_info['risk_level'],
                    'status': 'present'
                }
                
                # Análisis específico del valor del header
                if header_name == 'Strict-Transport-Security':
                    header_analysis['analysis'] = self._analyze_hsts(headers[header_name])
                elif header_name == 'Content-Security-Policy':
                    header_analysis['analysis'] = self._analyze_csp(headers[header_name])
                elif header_name == 'X-Frame-Options':
                    header_analysis['analysis'] = self._analyze_frame_options(headers[header_name])
                
                results['security_analysis']['present_security_headers'].append(header_analysis)
            else:
                missing_header = {
                    'name': header_name,
                    'description': header_info['description'],
                    'risk_level': header_info['risk_level'],
                    'recommendation': header_info['recommendation'],
                    'status': 'missing'
                }
                results['security_analysis']['missing_security_headers'].append(missing_header)
    
    def _analyze_information_disclosure(self, headers, results):
        """
        Analiza headers que pueden revelar información sensible
        """
        for header_name in self.information_disclosure_headers:
            if header_name in headers:
                disclosure_info = {
                    'header': header_name,
                    'value': headers[header_name],
                    'risk': 'Information disclosure',
                    'recommendation': f'Considerar ocultar o modificar el header {header_name}'
                }
                results['security_analysis']['information_disclosure'].append(disclosure_info)
    
    def _analyze_cookies(self, headers, results):
        """
        Analiza las cookies y sus configuraciones de seguridad
        """
        set_cookie_headers = []
        
        # Obtener todos los headers Set-Cookie
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)
        
        for cookie_header in set_cookie_headers:
            cookie_analysis = self._analyze_single_cookie(cookie_header)
            results['cookie_analysis'].append(cookie_analysis)
    
    def _analyze_single_cookie(self, cookie_header):
        """
        Analiza una cookie individual
        """
        analysis = {
            'cookie_string': cookie_header,
            'secure': 'Secure' in cookie_header,
            'httponly': 'HttpOnly' in cookie_header,
            'samesite': None,
            'domain': None,
            'path': None,
            'max_age': None,
            'security_issues': []
        }
        
        # Extraer atributos de la cookie
        if 'SameSite=' in cookie_header:
            samesite_match = re.search(r'SameSite=([^;]+)', cookie_header)
            if samesite_match:
                analysis['samesite'] = samesite_match.group(1).strip()
        
        if 'Domain=' in cookie_header:
            domain_match = re.search(r'Domain=([^;]+)', cookie_header)
            if domain_match:
                analysis['domain'] = domain_match.group(1).strip()
        
        if 'Path=' in cookie_header:
            path_match = re.search(r'Path=([^;]+)', cookie_header)
            if path_match:
                analysis['path'] = path_match.group(1).strip()
        
        # Identificar problemas de seguridad
        if not analysis['secure']:
            analysis['security_issues'].append('Cookie no tiene flag Secure')
        
        if not analysis['httponly']:
            analysis['security_issues'].append('Cookie no tiene flag HttpOnly')
        
        if not analysis['samesite']:
            analysis['security_issues'].append('Cookie no tiene atributo SameSite')
        
        return analysis
    
    def _analyze_hsts(self, hsts_value):
        """
        Analiza el header HSTS
        """
        analysis = {'issues': [], 'recommendations': []}
        
        if 'max-age=' not in hsts_value.lower():
            analysis['issues'].append('Falta directiva max-age')
        else:
            max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # 1 año
                    analysis['recommendations'].append('Considerar aumentar max-age a al menos 1 año')
        
        if 'includesubdomains' not in hsts_value.lower():
            analysis['recommendations'].append('Considerar agregar includeSubDomains')
        
        if 'preload' not in hsts_value.lower():
            analysis['recommendations'].append('Considerar agregar preload para mayor seguridad')
        
        return analysis
    
    def _analyze_csp(self, csp_value):
        """
        Analiza el header Content Security Policy
        """
        analysis = {'directives': [], 'issues': [], 'recommendations': []}
        
        # Extraer directivas
        directives = [d.strip() for d in csp_value.split(';') if d.strip()]
        analysis['directives'] = directives
        
        # Buscar problemas comunes
        if "'unsafe-inline'" in csp_value:
            analysis['issues'].append("Uso de 'unsafe-inline' reduce la seguridad")
        
        if "'unsafe-eval'" in csp_value:
            analysis['issues'].append("Uso de 'unsafe-eval' reduce la seguridad")
        
        if 'default-src' not in csp_value:
            analysis['recommendations'].append('Considerar agregar default-src')
        
        return analysis
    
    def _analyze_frame_options(self, frame_options_value):
        """
        Analiza el header X-Frame-Options
        """
        analysis = {'value': frame_options_value, 'security_level': 'unknown'}
        
        value_lower = frame_options_value.lower()
        if value_lower == 'deny':
            analysis['security_level'] = 'high'
        elif value_lower == 'sameorigin':
            analysis['security_level'] = 'medium'
        elif value_lower.startswith('allow-from'):
            analysis['security_level'] = 'low'
            analysis['note'] = 'ALLOW-FROM está deprecado, usar CSP frame-ancestors'
        
        return analysis
    
    def _calculate_security_score(self, results):
        """
        Calcula una puntuación de seguridad basada en los headers
        """
        score = 0
        max_score = len(self.security_headers) * 10
        
        # Puntos por headers de seguridad presentes
        for header in results['security_analysis']['present_security_headers']:
            if header['risk_level'] == 'high':
                score += 10
            elif header['risk_level'] == 'medium':
                score += 7
            elif header['risk_level'] == 'low':
                score += 5
        
        # Penalización por divulgación de información
        score -= len(results['security_analysis']['information_disclosure']) * 2
        
        # Penalización por cookies inseguras
        for cookie in results['cookie_analysis']:
            score -= len(cookie['security_issues'])
        
        # Asegurar que el score no sea negativo
        score = max(0, score)
        
        results['security_analysis']['security_score'] = {
            'score': score,
            'max_score': max_score,
            'percentage': round((score / max_score) * 100, 2) if max_score > 0 else 0,
            'grade': self._get_security_grade(score, max_score)
        }

    def to_frontend_format(self, results):
  
        vulnerabilities = []

        # Headers de seguridad faltantes
        for h in results['security_analysis']['missing_security_headers']:
            vulnerabilities.append({
                "type": "Header de Seguridad Faltante",
                "severity": h['risk_level'].capitalize(),
                "evidence": f"Falta el header {h['name']}: {h['description']}"
            })

        # Información expuesta
        for h in results['security_analysis']['information_disclosure']:
            vulnerabilities.append({
                "type": "Divulgación de Información",
                "severity": "Low",
                "evidence": f"Header {h['header']}: {h['value']}"
            })

        # Cookies inseguras
        for c in results['cookie_analysis']:
            for issue in c['security_issues']:
                vulnerabilities.append({
                    "type": "Configuración insegura de Cookie",
                    "severity": "Low",
                    "evidence": f"{issue} en cookie: {c['cookie_string']}"
                })
        print("estoy aca")

        return {"vulnerabilities": vulnerabilities}

    
    def _get_security_grade(self, score, max_score):
        """
        Asigna una calificación basada en la puntuación
        """
        percentage = (score / max_score) * 100 if max_score > 0 else 0
        
        if percentage >= 90:
            return 'A'
        elif percentage >= 80:
            return 'B'
        elif percentage >= 70:
            return 'C'
        elif percentage >= 60:
            return 'D'
        else:
            return 'F'

