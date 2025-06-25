import requests
import re
from urllib.parse import urljoin
from datetime import datetime

class SecretScanner:
    def __init__(self):
        # Patrones de expresiones regulares para detectar secretos
        self.secret_patterns = {
            'api_keys': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
                r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
                r'api[_-]?secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})',
                r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'
            ],
            'google_api': [
                r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
                r'google[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{39})'
            ],
            'github_tokens': [
                r'ghp_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
                r'github[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{40})'
            ],
            'jwt_tokens': [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',  # JWT Token
            ],
            'database_urls': [
                r'mysql://[^\\s]+',
                r'postgresql://[^\\s]+',
                r'mongodb://[^\\s]+',
                r'redis://[^\\s]+',
                r'sqlite://[^\\s]+'
            ],
            'email_passwords': [
                r'password["\']?\s*[:=]\s*["\']?([^"\'\\s]{8,})',
                r'passwd["\']?\s*[:=]\s*["\']?([^"\'\\s]{8,})',
                r'pwd["\']?\s*[:=]\s*["\']?([^"\'\\s]{8,})'
            ],
            'private_keys': [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----'
            ],
            'slack_tokens': [
                r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
                r'slack[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{50,})'
            ],
            'discord_tokens': [
                r'[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}',
                r'discord[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{50,})'
            ]
        }
        
        # Archivos comunes donde buscar secretos
        self.target_files = [
            '.env', '.env.local', '.env.production', '.env.development',
            'config.js', 'config.json', 'config.php', 'config.ini',
            'settings.py', 'settings.js', 'app.config',
            'web.config', 'application.properties',
            'docker-compose.yml', 'Dockerfile',
            'package.json', 'composer.json',
            'wp-config.php', 'database.php'
        ]
    
    def scan_secrets(self, target_url):
        """
        Escanea secretos en archivos comunes y contenido web
        """
        results = {
            'target': target_url,
            'scan_time': datetime.now().isoformat(),
            'secrets_found': [],
            'files_scanned': [],
            'errors': []
        }
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Escanear archivos específicos
        for filename in self.target_files:
            file_url = urljoin(target_url, filename)
            self._scan_file_for_secrets(file_url, filename, results)
        
        # Escanear la página principal
        self._scan_page_for_secrets(target_url, 'index', results)
        
        return results
    
    def _scan_file_for_secrets(self, file_url, filename, results):
        """
        Escanea un archivo específico en busca de secretos
        """
        try:
            response = requests.get(
                file_url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                results['files_scanned'].append({
                    'filename': filename,
                    'url': file_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                })
                
                # Buscar secretos en el contenido
                content = response.text
                self._analyze_content_for_secrets(content, file_url, filename, results)
                
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo a {filename}: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado con {filename}: {str(e)}")
    
    def _scan_page_for_secrets(self, page_url, page_name, results):
        """
        Escanea una página web en busca de secretos en el código fuente
        """
        try:
            response = requests.get(
                page_url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            if response.status_code == 200:
                results['files_scanned'].append({
                    'filename': page_name,
                    'url': page_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content)
                })
                
                # Buscar secretos en el código fuente HTML y JavaScript
                content = response.text
                self._analyze_content_for_secrets(content, page_url, page_name, results)
                
        except requests.exceptions.RequestException as e:
            results['errors'].append(f"Error accediendo a la página {page_name}: {str(e)}")
        except Exception as e:
            results['errors'].append(f"Error inesperado con la página {page_name}: {str(e)}")
    
    def _analyze_content_for_secrets(self, content, url, source, results):
        """
        Analiza el contenido en busca de patrones de secretos
        """
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Obtener contexto alrededor del match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\\n', ' ').strip()
                    
                    secret_info = {
                        'type': secret_type,
                        'pattern': pattern,
                        'match': match.group(0),
                        'context': context,
                        'source': source,
                        'url': url,
                        'line_number': content[:match.start()].count('\\n') + 1,
                        'severity': self._get_severity(secret_type)
                    }
                    
                    results['secrets_found'].append(secret_info)
    
    def _get_severity(self, secret_type):
        """
        Determina la severidad del secreto encontrado
        """
        high_severity = ['aws_keys', 'private_keys', 'database_urls']
        medium_severity = ['api_keys', 'github_tokens', 'jwt_tokens', 'slack_tokens']
        
        if secret_type in high_severity:
            return 'HIGH'
        elif secret_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def scan_custom_patterns(self, target_url, custom_patterns):
        """
        Escanea usando patrones personalizados
        """
        # Agregar patrones personalizados temporalmente
        original_patterns = self.secret_patterns.copy()
        self.secret_patterns['custom'] = custom_patterns
        
        results = self.scan_secrets(target_url)
        
        # Restaurar patrones originales
        self.secret_patterns = original_patterns
        
        return results

    def to_frontend_format(self, results):
        formatted = []

        for secret in results.get('secrets_found', []):
            formatted.append({
                "type": f"Secreto detectado - {secret['type']}",
                "severity": secret['severity'].capitalize(),
                "evidence": f"Match: {secret['match']}\nFuente: {secret['source']} ({secret['url']})\nContexto: {secret['context'][:150]}..."
            })

        return {"vulnerabilities": formatted}


