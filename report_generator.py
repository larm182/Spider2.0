import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os
import io
import base64
import pandas as pd
import numpy as np

class ReportGenerator:
    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Set matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        sns.set_style("whitegrid")
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.HexColor('#3498db'),
            alignment=TA_LEFT,
            fontName='Helvetica-Bold'
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=15,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_LEFT,
            fontName='Helvetica-Bold'
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            textColor=colors.HexColor('#34495e'),
            alignment=TA_LEFT,
            leftIndent=20,
            rightIndent=20,
            leading=14
        ))
        
        # Vulnerability item style
        self.styles.add(ParagraphStyle(
            name='VulnerabilityItem',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            textColor=colors.HexColor('#7f8c8d'),
            alignment=TA_LEFT,
            bulletIndent=10,
            leftIndent=20
        ))
    
    def generate_comprehensive_report(self, scan_results, target_url):
        """Generate a comprehensive security report with all scan results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Reporte_Spider_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build report content
        story = []
        
        # Title page
        story.extend(self._create_title_page(target_url, scan_results))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(scan_results))
        story.append(PageBreak())
        
        # Vulnerability overview with charts
        story.extend(self._create_vulnerability_overview(scan_results))
        story.append(PageBreak())
        
        # Detailed findings
        story.extend(self._create_detailed_findings(scan_results))
        story.append(PageBreak())
        
        # Recommendations
        story.extend(self._create_recommendations(scan_results))
        story.append(PageBreak())
        
        # Technical appendix
        story.extend(self._create_technical_appendix(scan_results))
        
        # Build PDF
        doc.build(story)
        
        return filepath
    
    def _create_title_page(self, target_url, scan_results):
        """Create the title page of the report"""
        story = []
        
        # Main title
        story.append(Paragraph("REPORTE DE SEGURIDAD WEB", self.styles['CustomTitle']))
        story.append(Spacer(1, 30))
        
        # Target information
        story.append(Paragraph(f"<b>Objetivo:</b> {target_url}", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 20))
        
        # Scan information
        scan_date = datetime.now().strftime("%d de %B de %Y")
        story.append(Paragraph(f"<b>Fecha del escaneo:</b> {scan_date}", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Scan types
        scan_types = self._extract_scan_types(scan_results)
        story.append(Paragraph(f"<b>Tipos de escaneo:</b> {', '.join(scan_types)}", self.styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Summary statistics
        stats = self._calculate_overall_statistics(scan_results)
        
        # Create summary table
        summary_data = [
            ['Métrica', 'Valor'],
            ['Total de vulnerabilidades', str(stats['total_vulnerabilities'])],
            ['Severidad alta', str(stats['high_severity'])],
            ['Severidad media', str(stats['medium_severity'])],
            ['Severidad baja', str(stats['low_severity'])],
            ['Puntuación de riesgo', f"{stats['risk_score']}/100"]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 50))
        
        # Footer
        story.append(Paragraph("Spider 2.0 Escáner de Vulnerabilidades Web - Herramienta de Análisis de Seguridad", 
                              self.styles['Normal']))
        
        return story
    
    def _create_executive_summary(self, scan_results):
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("RESUMEN EJECUTIVO", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Calculate statistics
        stats = self._calculate_overall_statistics(scan_results)
        
        # Generate executive summary text
        summary_text = self._generate_executive_summary_text(stats)
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 30))
        
        # Risk assessment chart
        risk_chart_path = self._create_risk_assessment_chart(stats)
        if risk_chart_path:
            story.append(Paragraph("Evaluación de Riesgo", self.styles['SectionHeader']))
            story.append(Image(risk_chart_path, width=5*inch, height=3*inch))
            story.append(Spacer(1, 20))
        
        return story
    
    def _create_vulnerability_overview(self, scan_results):
        """Create vulnerability overview with charts"""
        story = []
        
        story.append(Paragraph("RESUMEN DE VULNERABILIDADES", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Severity distribution chart
        severity_chart_path = self._create_severity_distribution_chart(scan_results)
        if severity_chart_path:
            story.append(Paragraph("Distribución por Severidad", self.styles['SectionHeader']))
            story.append(Image(severity_chart_path, width=5*inch, height=4*inch))
            story.append(Spacer(1, 20))
        
        # Vulnerability types chart
        types_chart_path = self._create_vulnerability_types_chart(scan_results)
        if types_chart_path:
            story.append(Paragraph("Tipos de Vulnerabilidades", self.styles['SectionHeader']))
            story.append(Image(types_chart_path, width=5*inch, height=4*inch))
            story.append(Spacer(1, 20))
        
        # Scan modules results
        modules_chart_path = self._create_scan_modules_chart(scan_results)
        if modules_chart_path:
            story.append(Paragraph("Resultados por Módulo de Escaneo", self.styles['SectionHeader']))
            story.append(Image(modules_chart_path, width=5*inch, height=4*inch))
            story.append(Spacer(1, 20))
        
        return story
    
    def _create_detailed_findings(self, scan_results):
        """Create detailed findings section"""
        story = []
        
        story.append(Paragraph("HALLAZGOS DETALLADOS", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Process each scan type
        for scan_type, results in scan_results.items():
            if scan_type in ['target', 'scan_time', 'status']:
                continue
                
            story.append(Paragraph(f"{scan_type.upper().replace('_', ' ')}", self.styles['SectionHeader']))
            
            # Add scan-specific findings
            findings = self._extract_findings_for_scan_type(scan_type, results)
            
            if findings:
                for finding in findings:
                    story.append(Paragraph(f"<b>• {finding['title']}</b>", self.styles['Normal']))
                    story.append(Paragraph(f"  Severidad: {finding['severity']}", self.styles['Normal']))
                    story.append(Paragraph(f"  Descripción: {finding['description']}", self.styles['Normal']))
                    story.append(Spacer(1, 10))
            else:
                story.append(Paragraph("No se encontraron vulnerabilidades en este módulo.", self.styles['Normal']))
            
            story.append(Spacer(1, 20))
        
        return story
    
    def _create_recommendations(self, scan_results):
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("RECOMENDACIONES", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(scan_results)
        
        for i, recommendation in enumerate(recommendations, 1):
            story.append(Paragraph(f"<b>{i}. {recommendation['title']}</b>", self.styles['SectionHeader']))
            story.append(Paragraph(f"<b>Prioridad:</b> {recommendation['priority']}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Descripción:</b> {recommendation['description']}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Pasos de implementación:</b>", self.styles['Normal']))
            
            for step in recommendation['steps']:
                story.append(Paragraph(f"• {step}", self.styles['Normal']))
            
            story.append(Spacer(1, 20))
        
        return story
    
    def _create_technical_appendix(self, scan_results):
        """Create technical appendix"""
        story = []
        
        story.append(Paragraph("APÉNDICE TÉCNICO", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Scan configuration
        story.append(Paragraph("Configuración del Escaneo", self.styles['SectionHeader']))
        story.append(Paragraph("Los siguientes módulos fueron ejecutados durante el escaneo:", self.styles['Normal']))
        
        scan_types = self._extract_scan_types(scan_results)
        for scan_type in scan_types:
            story.append(Paragraph(f"• {scan_type}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # Methodology
        story.append(Paragraph("Metodología", self.styles['SectionHeader']))
        methodology_text = """
        El escaneo de vulnerabilidades se realizó utilizando una combinación de técnicas automatizadas
        que incluyen análisis de puertos, detección de directorios, búsqueda de secretos expuestos,
        pruebas de inyección SQL, detección de XSS, análisis de headers de seguridad, y evaluación
        de configuraciones de seguridad. Cada módulo utiliza patrones y firmas específicas para
        identificar vulnerabilidades conocidas y configuraciones inseguras.
        """
        story.append(Paragraph(methodology_text, self.styles['Normal']))
        
        return story
    
    def _create_severity_distribution_chart(self, scan_results):
        """Create severity distribution donut chart"""
        try:
            stats = self._calculate_overall_statistics(scan_results)
            
            # Data for chart
            labels = ['Alta', 'Media', 'Baja']
            sizes = [stats['high_severity'], stats['medium_severity'], stats['low_severity']]
            colors_list = ['#e74c3c', '#f39c12', '#27ae60']
            explode = (0.05, 0.02, 0)  # Slight separation for slices
            
            # Only include non-zero values
            filtered_data = [(label, size, color) for label, size, color in zip(labels, sizes, colors_list) if size > 0]
            
            if not filtered_data:
                return None
            
            labels, sizes, colors_list = zip(*filtered_data)
            
            # Create figure
            fig, ax = plt.subplots(figsize=(8, 6), subplot_kw=dict(aspect="equal"))
            
            # Create donut chart
            wedges, texts, autotexts = ax.pie(
                sizes, 
                explode=explode[:len(sizes)], 
                labels=labels, 
                colors=colors_list,
                autopct=lambda p: f'{p:.1f}%' if p > 5 else '',
                startangle=90,
                pctdistance=0.85,
                textprops={'fontsize': 10, 'fontweight': 'bold'}
            )
            
            # Draw white circle in center for donut effect
            centre_circle = plt.Circle((0,0), 0.70, fc='white')
            fig.gca().add_artist(centre_circle)
            
            # Equal aspect ratio ensures pie is drawn as a circle
            ax.axis('equal')  
            
            # Add count in center
            plt.text(0, 0, f"Total\n{sum(sizes)}", 
                    ha='center', va='center', 
                    fontsize=14, fontweight='bold')
            
            # Title and legend
            plt.title('Distribución de Vulnerabilidades por Severidad', 
                     fontsize=14, fontweight='bold', pad=20)
            plt.legend(wedges, labels,
                      title="Severidad",
                      loc="center left",
                      bbox_to_anchor=(1, 0, 0.5, 1))
            
            # Adjust layout
            plt.tight_layout()
            
            # Save chart
            chart_path = os.path.join(self.output_dir, 'severity_distribution.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
        except Exception as e:
            print(f"Error creating severity chart: {e}")
            return None

    def _create_vulnerability_types_chart(self, scan_results):
        """Create horizontal bar chart for vulnerability types"""
        try:
            # Extract vulnerability types
            vuln_types = {}
            
            for scan_type, results in scan_results.items():
                if scan_type in ['target', 'scan_time', 'status']:
                    continue
                
                # Count vulnerabilities by type
                if isinstance(results, dict) and 'vulnerabilities' in results:
                    for vuln in results['vulnerabilities']:
                        vuln_type = vuln.get('type', 'Unknown')
                        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            if not vuln_types:
                return None
            
            # Sort by count and limit to top 10
            sorted_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_types) > 10:
                sorted_types = sorted_types[:10]
            
            types = [t[0] for t in sorted_types]
            counts = [t[1] for t in sorted_types]
            
            # Create horizontal bar chart
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Use a color gradient based on count
            colors = plt.cm.viridis(np.linspace(0.2, 0.8, len(types)))
            
            bars = ax.barh(types, counts, color=colors, alpha=0.8)
            
            # Add value labels
            for bar in bars:
                width = bar.get_width()
                ax.text(width + 0.2, bar.get_y() + bar.get_height()/2,
                        f'{int(width)}', 
                        va='center', ha='left',
                        fontsize=10, fontweight='bold')
            
            # Formatting
            ax.set_xlabel('Número de Vulnerabilidades', fontweight='bold')
            ax.set_title('Top 10 Tipos de Vulnerabilidades', 
                        fontsize=14, fontweight='bold', pad=20)
            
            # Remove spines
            ax.spines['right'].set_visible(False)
            ax.spines['top'].set_visible(False)
            
            # Grid lines
            ax.xaxis.grid(True, linestyle='--', alpha=0.6)
            
            plt.tight_layout()
            
            # Save chart
            chart_path = os.path.join(self.output_dir, 'vulnerability_types.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
        except Exception as e:
            print(f"Error creating vulnerability types chart: {e}")
            return None
    
    
    def _create_scan_modules_chart(self, scan_results):
        """Create scan modules results chart with stacked bars by severity"""
        try:
            # Extract scan module results by severity
            modules = []
            high_counts = []
            medium_counts = []
            low_counts = []
            
            for scan_type, results in scan_results.items():
                if scan_type in ['target', 'scan_time', 'status']:
                    continue
                
                modules.append(scan_type.replace('_', ' ').title())
                
                # Count vulnerabilities by severity for this module
                high = 0
                medium = 0
                low = 0
                
                if isinstance(results, dict) and 'vulnerabilities' in results:
                    for vuln in results['vulnerabilities']:
                        severity = vuln.get('severity', 'Low').lower()
                        if severity == 'high':
                            high += 1
                        elif severity == 'medium':
                            medium += 1
                        else:
                            low += 1
                
                high_counts.append(high)
                medium_counts.append(medium)
                low_counts.append(low)
            
            if not modules:
                return None
            
            # Create stacked bar chart
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Plot bars
            bar1 = ax.bar(modules, high_counts, color='#e74c3c', label='Alta')
            bar2 = ax.bar(modules, medium_counts, bottom=high_counts, color='#f39c12', label='Media')
            bar3 = ax.bar(modules, low_counts, bottom=np.array(high_counts)+np.array(medium_counts), 
                         color='#27ae60', label='Baja')
            
            # Add total labels
            totals = np.array(high_counts) + np.array(medium_counts) + np.array(low_counts)
            
            for i, total in enumerate(totals):
                if total > 0:
                    ax.text(i, total + 0.2, f'{int(total)}', 
                           ha='center', va='bottom',
                           fontsize=9, fontweight='bold')
            
            # Formatting
            ax.set_ylabel('Número de Vulnerabilidades', fontweight='bold')
            ax.set_title('Vulnerabilidades por Módulo y Severidad', 
                        fontsize=14, fontweight='bold', pad=20)
            
            # Rotate x-labels
            plt.xticks(rotation=45, ha='right')
            
            # Legend
            ax.legend(loc='upper right', frameon=True)
            
            # Remove spines
            ax.spines['right'].set_visible(False)
            ax.spines['top'].set_visible(False)
            
            # Grid lines
            ax.yaxis.grid(True, linestyle='--', alpha=0.6)
            
            plt.tight_layout()
            
            # Save chart
            chart_path = os.path.join(self.output_dir, 'scan_modules.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
        except Exception as e:
            print(f"Error creating scan modules chart: {e}")
            return None

    def _create_risk_assessment_chart(self, stats):
        """Create enhanced risk assessment gauge chart"""
        try:
            risk_score = stats['risk_score']
            
            # Create figure
            fig, ax = plt.subplots(figsize=(10, 6), subplot_kw={'projection': 'polar'})
            
            # Define parameters
            max_score = 100
            theta_range = np.linspace(0, np.pi, 100)
            bottom = 0.5
            width = 0.2
            
            # Define risk levels with colors and ranges
            risk_levels = [
                {'min': 0, 'max': 30, 'color': '#27ae60', 'label': 'Bajo'},
                {'min': 30, 'max': 60, 'color': '#f39c12', 'label': 'Medio'},
                {'min': 60, 'max': 100, 'color': '#e74c3c', 'label': 'Alto'}
            ]
            
            # Create colored arcs for each risk level
            for level in risk_levels:
                theta_min = np.pi * (level['min'] / max_score)
                theta_max = np.pi * (level['max'] / max_score)
                theta = np.linspace(theta_min, theta_max, 50)
                r = np.ones_like(theta) * bottom
                
                ax.fill_between(theta, r, r + width, 
                               color=level['color'], 
                               alpha=0.7,
                               label=f"{level['label']} ({level['min']}-{level['max']})")
            
            # Add needle
            needle_angle = np.pi * (risk_score / max_score)
            ax.plot([needle_angle, needle_angle], [bottom - 0.1, bottom + width + 0.1], 
                    color='black', linewidth=2)
            ax.scatter(needle_angle, bottom + width/2, color='black', s=100, zorder=5)
            
            # Add score text
            ax.text(0, 0.2, f'{risk_score}', 
                   ha='center', va='center', 
                   fontsize=24, fontweight='bold')
            ax.text(0, 0, 'Puntuación de Riesgo', 
                   ha='center', va='center', 
                   fontsize=12)
            
            # Customize plot
            ax.set_theta_zero_location('N')
            ax.set_theta_direction(-1)
            ax.set_ylim(0, bottom + width + 0.1)
            ax.set_xticks(np.linspace(0, np.pi, 5))
            ax.set_xticklabels(['0', '25', '50', '75', '100'])
            ax.grid(False)
            ax.spines['polar'].set_visible(False)
            
            # Add legend
            ax.legend(bbox_to_anchor=(1.1, 1.1), loc='upper right')
            
            # Title
            plt.title('Evaluación de Riesgo de Seguridad', 
                     fontsize=16, fontweight='bold', pad=20)
            
            # Save chart
            chart_path = os.path.join(self.output_dir, 'risk_assessment.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
        except Exception as e:
            print(f"Error creating risk assessment chart: {e}")
            return None
    
    def _calculate_overall_statistics(self, scan_results):
        """Calculate overall statistics from scan results"""
        stats = {
            'total_vulnerabilities': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'risk_score': 0
        }
        
        for scan_type, results in scan_results.items():
            if scan_type in ['target', 'scan_time', 'status']:
                continue
            
            if isinstance(results, dict) and 'vulnerabilities' in results:
                vulnerabilities = results['vulnerabilities']
                stats['total_vulnerabilities'] += len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Low').lower()
                    if severity == 'high':
                        stats['high_severity'] += 1
                    elif severity == 'medium':
                        stats['medium_severity'] += 1
                    else:
                        stats['low_severity'] += 1
        
        # Calculate risk score
        stats['risk_score'] = min(100, 
            stats['high_severity'] * 10 + 
            stats['medium_severity'] * 5 + 
            stats['low_severity'] * 2
        )
        
        return stats
    
    def _extract_scan_types(self, scan_results):
        """Extract scan types from results"""
        scan_types = []
        for key in scan_results.keys():
            if key not in ['target', 'scan_time', 'status']:
                scan_types.append(key.replace('_', ' ').title())
        return scan_types
    
    def _generate_executive_summary_text(self, stats):
        """Generate executive summary text based on statistics"""
        total_vulns = stats['total_vulnerabilities']
        risk_score = stats['risk_score']
        
        if total_vulns == 0:
            return """
            El análisis de seguridad no identificó vulnerabilidades críticas en el objetivo evaluado.
            Sin embargo, se recomienda mantener las mejores prácticas de seguridad y realizar
            evaluaciones periódicas para asegurar la postura de seguridad continua.
            """
        
        risk_level = "bajo" if risk_score < 30 else "medio" if risk_score < 60 else "alto"
        
        return f"""
        El análisis de seguridad identificó un total de {total_vulns} vulnerabilidades en el objetivo evaluado.
        La distribución incluye {stats['high_severity']} vulnerabilidades de severidad alta,
        {stats['medium_severity']} de severidad media, y {stats['low_severity']} de severidad baja.
        
        La puntuación de riesgo general es de {risk_score}/100, lo que indica un nivel de riesgo {risk_level}.
        Se recomienda priorizar la remediación de las vulnerabilidades de alta severidad y implementar
        las recomendaciones de seguridad proporcionadas en este reporte.
        """
    
    def _extract_findings_for_scan_type(self, scan_type, results):
        """Extract findings for a specific scan type"""
        findings = []
        
        if isinstance(results, dict) and 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                finding = {
                    'title': vuln.get('type', 'Vulnerabilidad detectada'),
                    'severity': vuln.get('severity', 'Low'),
                    'description': vuln.get('evidence', 'Vulnerabilidad identificada durante el escaneo')
                }
                findings.append(finding)
        
        return findings
    
    def _generate_recommendations(self, scan_results):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        stats = self._calculate_overall_statistics(scan_results)
        
        if stats['high_severity'] > 0:
            recommendations.append({
                'title': 'Remediar vulnerabilidades de alta severidad',
                'priority': 'Alta',
                'description': 'Las vulnerabilidades de alta severidad representan un riesgo inmediato para la seguridad.',
                'steps': [
                    'Revisar todas las vulnerabilidades de alta severidad identificadas',
                    'Implementar parches de seguridad disponibles',
                    'Configurar controles de seguridad adicionales',
                    'Verificar la efectividad de las correcciones'
                ]
            })
        
        if stats['medium_severity'] > 0:
            recommendations.append({
                'title': 'Abordar vulnerabilidades de severidad media',
                'priority': 'Media',
                'description': 'Las vulnerabilidades de severidad media deben ser abordadas en el corto plazo.',
                'steps': [
                    'Planificar la remediación de vulnerabilidades medias',
                    'Implementar controles compensatorios si es necesario',
                    'Actualizar configuraciones de seguridad',
                    'Documentar los cambios realizados'
                ]
            })
        
        recommendations.append({
            'title': 'Implementar monitoreo continuo',
            'priority': 'Media',
            'description': 'Establecer un programa de monitoreo continuo de seguridad.',
            'steps': [
                'Configurar herramientas de monitoreo de seguridad',
                'Establecer alertas para actividades sospechosas',
                'Realizar escaneos de vulnerabilidades regulares',
                'Mantener un registro de incidentes de seguridad'
            ]
        })
        
        return recommendations

