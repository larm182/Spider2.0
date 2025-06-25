import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
from urllib.parse import urljoin

class TechDetector:
    def __init__(self):
        # Firmas de tecnologías web comunes
        self.tech_signatures = {
            'cms': {
                'WordPress': [
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json',
                    r'wordpress'
                ],
                'Drupal': [
                    r'/sites/default/',
                    r'/modules/',
                    r'Drupal',
                    r'/misc/drupal.js'
                ],
                'Joomla': [
                    r'/components/',
                    r'/templates/',
                    r'Joomla',
                    r'/media/jui/'
                ],
                'Magento': [
                    r'/skin/frontend/',
                    r'/js/mage/',
                    r'Magento',
                    r'/media/catalog/'
                ]
            },
            'frameworks': {
                'Laravel': [
                    r'laravel_session',
                    r'/vendor/laravel/',
                    r'Laravel',
                    r'_token'
                ],
                'Django': [
                    r'csrfmiddlewaretoken',
                    r'Django',
                    r'/static/admin/',
                    r'django'
                ],
                'React': [
                    r'react',
                    r'React',
                    r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                    r'react-dom'
                ],
                'Angular': [
                    r'angular',
                    r'Angular',
                    r'ng-',
                    r'angularjs'
                ],
                'Vue.js': [
                    r'vue',
                    r'Vue',
                    r'v-',
                    r'vuejs'
                ]
            },
            'servers': {
                'Apache': [
                    r'Apache',
                    r'apache',
                    r'/icons/',
                    r'mod_'
                ],
                'Nginx': [
                    r'nginx',
                    r'Nginx',
                    r'X-Accel-',
                    r'nginx/'
                ],
                'IIS': [
                    r'IIS',
                    r'Microsoft-IIS',
                    r'X-Powered-By: ASP.NET',
                    r'aspnet'
                ]
            },
            'languages': {
                'PHP': [
                    r'\.php',
                    r'PHP',
                    r'X-Powered-By: PHP',
                    r'PHPSESSID'
                ],
                'ASP.NET': [
                    r'\.aspx',
                    r'ASP.NET',
                    r'X-Powered-By: ASP.NET',
                    r'__VIEWSTATE'
                ],
                'Java': [
                    r'\.jsp',
                    r'Java',
                    r'JSESSIONID',
                    r'X-Powered-By: Servlet'
                ],
                'Python': [
                    r'\.py',
                    r'Python',
                    r'Django',
                    r'Flask'
                ]
            },
            'databases': {
                'MySQL': [
                    r'mysql',
                    r'MySQL',
                    r'phpmyadmin',
                    r'mysqladmin'
                ],
                'PostgreSQL': [
                    r'postgresql',
                    r'PostgreSQL',
                    r'postgres',
                    r'pgadmin'
                ],
                'MongoDB': [
                    r'mongodb',
                    r'MongoDB',
                    r'mongo',
                    r'mongoexpress'
                ]
            },
            'analytics': {
                'Google Analytics': [
                    r'google-analytics',
                    r'gtag',
                    r'UA-',
                    r'GA_MEASUREMENT_ID'
                ],
                'Facebook Pixel': [
                    r'facebook.com/tr',
                    r'fbq',
                    r'facebook-pixel',
                    r'connect.facebook.net'
                ]
            }
        }
    
    def detect_technologies(self, target_url):
        """
        Detecta tecnologías utilizadas en el sitio web
        """
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'technologies': {},
            'headers': {},
            'meta_tags': [],
            'scripts': [],
            'links': [],
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
            
            # Analizar headers HTTP
            self._analyze_headers(response.headers, results)
            
            # Analizar contenido HTML
            if response.status_code == 200:
                self._analyze_html_content(response.text, results)
                self._detect_technologies_from_content(response.text, results)
            
            # Intentar detectar tecnologías adicionales
            self._detect_additional_technologies(target_url, results)
            
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo al sitio: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado: {str(e)}")
        
        return results
    
    def _analyze_headers(self, headers, results):
        """
        Analiza los headers HTTP para detectar tecnologías
        """
        results['headers'] = dict(headers)
        
        # Headers que revelan tecnologías
        tech_headers = {
            'Server': 'server',
            'X-Powered-By': 'framework',
            'X-Generator': 'generator',
            'X-Drupal-Cache': 'cms',
            'X-Mod-Pagespeed': 'optimization'
        }
        
        for header, tech_type in tech_headers.items():
            if header in headers:
                if tech_type not in results['technologies']:
                    results['technologies'][tech_type] = []
                results['technologies'][tech_type].append({
                    'name': headers[header],
                    'source': f'HTTP Header: {header}',
                    'confidence': 'high'
                })
    
    def _analyze_html_content(self, html_content, results):
        """
        Analiza el contenido HTML para extraer información
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Analizar meta tags
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                meta_info = {}
                if meta.get('name'):
                    meta_info['name'] = meta.get('name')
                if meta.get('content'):
                    meta_info['content'] = meta.get('content')
                if meta.get('property'):
                    meta_info['property'] = meta.get('property')
                if meta_info:
                    results['meta_tags'].append(meta_info)
            
            # Analizar scripts
            scripts = soup.find_all('script')
            for script in scripts:
                script_info = {}
                if script.get('src'):
                    script_info['src'] = script.get('src')
                if script.string:
                    script_info['inline'] = script.string[:200] + '...' if len(script.string) > 200 else script.string
                if script_info:
                    results['scripts'].append(script_info)
            
            # Analizar links CSS
            links = soup.find_all('link')
            for link in links:
                if link.get('href'):
                    link_info = {
                        'href': link.get('href'),
                        'rel': link.get('rel'),
                        'type': link.get('type')
                    }
                    results['links'].append(link_info)
                    
        except Exception as e:
            results['errors'].append(f"Error analizando HTML: {str(e)}")
    
    def _detect_technologies_from_content(self, content, results):
        """
        Detecta tecnologías basándose en patrones en el contenido
        """
        for category, technologies in self.tech_signatures.items():
            for tech_name, patterns in technologies.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        if category not in results['technologies']:
                            results['technologies'][category] = []
                        
                        # Evitar duplicados
                        existing = [t for t in results['technologies'][category] if t['name'] == tech_name]
                        if not existing:
                            results['technologies'][category].append({
                                'name': tech_name,
                                'source': f'Content pattern: {pattern}',
                                'confidence': 'medium'
                            })
    
    def _detect_additional_technologies(self, target_url, results):
        """
        Detecta tecnologías adicionales mediante peticiones específicas
        """
        # Archivos comunes que revelan tecnologías
        test_files = [
            ('robots.txt', 'configuration'),
            ('sitemap.xml', 'seo'),
            ('wp-admin/', 'WordPress'),
            ('admin/', 'admin_panel'),
            ('phpmyadmin/', 'phpMyAdmin'),
            ('.well-known/security.txt', 'security')
        ]
        
        for file_path, tech_type in test_files:
            try:
                test_url = urljoin(target_url, file_path)
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302]:
                    if 'additional' not in results['technologies']:
                        results['technologies']['additional'] = []
                    
                    results['technologies']['additional'].append({
                        'name': tech_type,
                        'source': f'File exists: {file_path}',
                        'confidence': 'medium',
                        'status_code': response.status_code
                    })
                    
            except requests.exceptions.RequestException:
                # Ignorar errores en peticiones adicionales
                pass
    
    def get_technology_summary(self, results):
        """
        Genera un resumen de las tecnologías detectadas
        """
        summary = {
            'total_technologies': 0,
            'categories': {},
            'high_confidence': [],
            'medium_confidence': [],
            'low_confidence': []
        }
        
        for category, techs in results['technologies'].items():
            summary['categories'][category] = len(techs)
            summary['total_technologies'] += len(techs)
            
            for tech in techs:
                confidence = tech.get('confidence', 'low')
                tech_entry = f"{tech['name']} ({category})"
                
                if confidence == 'high':
                    summary['high_confidence'].append(tech_entry)
                elif confidence == 'medium':
                    summary['medium_confidence'].append(tech_entry)
                else:
                    summary['low_confidence'].append(tech_entry)
        
        return summary

    def _analyze_content_for_secrets(self, content, url, source, results):
        """
        Analiza el contenido en busca de patrones de secretos evitando duplicados por valor real.
        """
        seen_values = set()

        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Extraer valor real
                    if match.groups():
                        secret_value = match.group(1).strip()
                    else:
                        # extraer entre comillas si existe: apikey = "value"
                        raw = match.group(0)
                        secret_value = re.findall(r'["\']?([A-Za-z0-9_\/+=\-]{8,})["\']?', raw)
                        secret_value = secret_value[0] if secret_value else raw.strip()

                    key = (secret_type, secret_value, url)
                    if key in seen_values:
                        continue  # Duplicado
                    seen_values.add(key)

                    # Obtener contexto
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\\n', ' ').strip()

                    secret_info = {
                        'type': secret_type,
                        'pattern': pattern,
                        'match': secret_value,
                        'context': context,
                        'source': source,
                        'url': url,
                        'line_number': content[:match.start()].count('\n') + 1,
                        'severity': self._get_severity(secret_type)
                    }

                    print(secret_info)

                    results['secrets_found'].append(secret_info)

    def to_frontend_format(self, raw_result):
        """
        Formatea los resultados para que el frontend los interprete como vulnerabilidades informativas.
        """
        technologies = raw_result.get("technologies", {})
        errors = raw_result.get("errors", [])

        vulnerabilities = []

        for category, techs in technologies.items():
            for tech in techs:
                vuln = {
                    "type": f"Tecnología ({category})",
                    "severity": "Info",
                    "evidence": f"Detectado: {tech['name']} (Fuente: {tech['source']}, Confianza: {tech['confidence']})",
                    "payload": tech["name"],
                    "url": raw_result.get("target", ""),
                    "parameter": category,
                    "method": "GET"
                }
                vulnerabilities.append(vuln)

        return {
            "vulnerabilities": vulnerabilities,
            "errors": errors
        }




