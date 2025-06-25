# Acerca de Spider 2.0 Escáner de Vulnerabilidades Web

# 🔍 Descripción

Spider es una herramienta de seguridad en Python diseñada para realizar análisis automatizados en sitios web. Permite detectar vulnerabilidades comunes, recopilar información del servidor y generar informes detallados en PDF con los hallazgos obtenidos.

Esta herramienta es ideal para pentesters, profesionales de ciberseguridad y administradores de sistemas que deseen evaluar la seguridad de sus aplicaciones web de manera eficiente.

# ⚡ Características Principales

✅ Enumeración de Directorios y Archivos: Busca directorios y scripts expuestos en la aplicación web.

✅ Detección de Vulnerabilidades:

XSS (Cross-Site Scripting): Identifica posibles puntos de inyección de scripts maliciosos.

SQL Injection: Detecta vulnerabilidades de inyección SQL que podrían comprometer la base de datos.

Command Injection: Verifica si el servidor es vulnerable a inyecciones de comandos del sistema.

LFI: Verifica vulnerabilidad web que permite la lectura de archivos locales.

✅ Escaneo de Puertos y Tecnologías: Obtiene información sobre los servicios y tecnologías que ejecuta el servidor.

✅ Revisión de Encabezados HTTP: Identifica configuraciones inseguras en los headers del sitio web.

✅ Fuerza Bruta y Validación de Credenciales: Pruebas básicas de acceso con diccionarios personalizados.

✅ Generación de Reportes en PDF: Se incluyen tablas detalladas, gráficas de estadísticas y una descripción clara de los hallazgos.

# 🚀 Instalación

Clona el repositorio: git clone https://github.com/larm182/Spider2.0

Accede al directorio: cd Spider2.0

Instala las dependencias: pip install -r requirements.txt

Ejecuta la herramienta: python app.py

# 📊 Ejemplo de Uso

El usuario puede seleccionar diferentes opciones del menú interactivo, por ejemplo:

1. Agregue la URL para se analizada

2. Eliga la Opcion

3. Resultados

4. Generar PDF

Tras la ejecución, se generará un informe detallado con los resultados encontrados.

# 📄 Ejemplo de Reporte

El informe en PDF incluirá:

Listado de vulnerabilidades encontradas.

URLs y payloads utilizados en las pruebas.

Tablas organizadas con la información recopilada.

Gráficas estadísticas sobre los hallazgos.

Recomendaciones para mitigar los riesgos.

# 📌 Requisitos

Python 3.8+
Librerías: requests, beautifulsoup4, fpdf, matplotlib, termcolor, python-nmap, etc.

# ⚠️ Aviso Legal

Esta herramienta ha sido desarrollada con fines educativos y de seguridad ofensiva ética. El uso indebido en sistemas sin autorización puede ser ilegal. El autor no se hace responsable por el mal uso de esta herramienta.
