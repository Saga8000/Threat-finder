from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from datetime import datetime
import os

def generate_pdf_report(analysis_data, output_path):
    """Generate a PDF report from analysis results."""
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        textColor=colors.HexColor('#1E40AF')
    )
    elements.append(Paragraph("Malware Forensic Analysis Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Disclaimer
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#DC2626'),
        spaceAfter=12
    )
    elements.append(Paragraph("DISCLAIMER: This report provides probabilistic threat attribution for educational purposes only. Results should not be used as the sole basis for security decisions.", disclaimer_style))
    elements.append(Spacer(1, 12))
    
    analysis_type = analysis_data.get('analysis_type', 'file')
    
    # File or URL Information
    if analysis_type == 'file':
        elements.append(Paragraph("File Information", styles['Heading2']))
        file_info = analysis_data['file_info']
        file_data = [
            ["Filename:", file_info['filename']],
            ["File Size:", f"{file_info['file_size'] / 1024:.2f} KB"],
            ["File Type:", file_info['file_type']],
            ["MD5:", file_info['md5']],
            ["SHA1:", file_info['sha1']],
            ["SHA256:", file_info['sha256']],
            ["Entropy:", f"{file_info['entropy']:.4f}"],
            ["Analysis Date:", file_info['analysis_date']]
        ]
    else:  # URL analysis
        elements.append(Paragraph("URL Information", styles['Heading2']))
        url_info = analysis_data['url_info']
        file_data = [
            ["URL:", url_info['original_url']],
            ["Domain:", url_info.get('hostname', 'N/A')],
            ["Scheme:", url_info['scheme']],
            ["Path:", url_info.get('path', '/')],
            ["URL Length:", f"{analysis_data.get('url_length', 0)} characters"],
            ["Domain Length:", f"{analysis_data.get('domain_length', 0)} characters"],
            ["Analysis Date:", url_info['analysis_date']]
        ]
    
    file_table = Table(file_data, colWidths=[1.5*inch, 4*inch])
    file_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4B5563')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
        ('FONTWEIGHT', (0, 0), (0, -1), 'BOLD'),
    ]))
    
    elements.append(file_table)
    elements.append(Spacer(1, 24))
    
    # Threat Assessment
    threat_score = analysis_data.get('threat_score', 0)
    threat_level = "High" if threat_score >= 70 else "Medium" if threat_score >= 30 else "Low"
    threat_color = colors.red if threat_score >= 70 else colors.orange if threat_score >= 30 else colors.green
    
    elements.append(Paragraph("Threat Assessment", styles['Heading2']))
    threat_data = [
        ["Threat Score:", f"{threat_score}/100"],
        ["Threat Level:", threat_level]
    ]
    
    threat_table = Table(threat_data, colWidths=[1.5*inch, 4*inch])
    threat_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4B5563')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
        ('FONTWEIGHT', (0, 0), (0, -1), 'BOLD'),
        ('TEXTCOLOR', (1, 1), (1, 1), threat_color),
        ('FONTWEIGHT', (1, 1), (1, 1), 'BOLD')
    ]))
    
    elements.append(threat_table)
    elements.append(Spacer(1, 24))
    
    # URL Analysis (URL analysis only)
    if analysis_type == 'url':
        elements.append(Paragraph("URL Analysis Results", styles['Heading2']))
        url_features = analysis_data.get('suspicious_indicators', {})
        
        url_data = [
            ["IP Address in Domain:", "Yes" if url_features.get('has_ip_in_domain') else "No"],
            ["Suspicious TLD:", "Yes" if url_features.get('has_suspicious_tld') else "No"],
            ["Long Subdomain:", "Yes" if url_features.get('has_long_subdomain') else "No"],
            ["Suspicious Words:", "Yes" if url_features.get('has_suspicious_words') else "No"],
            ["Encoded Characters:", "Yes" if url_features.get('has_encoded_chars') else "No"],
            ["@ Symbol:", "Yes" if url_features.get('has_at_symbol') else "No"],
            ["Double Slash in Path:", "Yes" if url_features.get('has_double_slash') else "No"],
            ["Suspicious Ports:", "Yes" if url_features.get('has_suspicious_ports') else "No"],
            ["HTTPS:", "Yes" if analysis_data.get('url_info', {}).get('scheme') == 'https' else "No"],
            ["Query Parameters:", str(url_features.get('query_param_count', 0))]
        ]
        
        url_table = Table(url_data, colWidths=[2*inch, 3.5*inch])
        url_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4B5563')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
            ('FONTWEIGHT', (0, 0), (0, -1), 'BOLD'),
        ]))
        
        elements.append(url_table)
        elements.append(Spacer(1, 24))
    
    # PE Information (File analysis only) (File analysis only)
    if analysis_type == 'file' and analysis_data.get('pe_info', {}).get('is_pe', False):
        elements.append(Paragraph("PE File Analysis", styles['Heading2']))
        pe_info = analysis_data['pe_info']
        
        pe_data = [
            ["Packed:", "Yes" if pe_info.get('is_packed') else "No"],
            ["Signed:", "Yes" if pe_info.get('is_signed') else "No"],
            ["Anti-Debug:", "Detected" if pe_info.get('has_anti_debug') else "Not Detected"],
            ["VM Evasion:", "Detected" if pe_info.get('has_vm_evasion') else "Not Detected"],
            ["Suspicious Imports:", str(pe_info.get('suspicious_imports', 0))],
            ["Suspicious Sections:", str(pe_info.get('suspicious_sections', 0))]
        ]
        
        pe_table = Table(pe_data, colWidths=[2*inch, 3.5*inch])
        pe_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4B5563')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
            ('FONTWEIGHT', (0, 0), (0, -1), 'BOLD'),
        ]))
        
        elements.append(pe_table)
        elements.append(Spacer(1, 12))
        
        # Sections
        if pe_info.get('sections'):
            elements.append(Paragraph("PE Sections", styles['Heading3']))
            section_data = [["Name", "Size", "Entropy", "Suspicious"]]
            
            for section in pe_info['sections']:
                section_data.append([
                    section['name'],
                    f"{section['size']} bytes",
                    f"{section['entropy']:.4f}",
                    "Yes" if section.get('is_suspicious', False) else "No"
                ])
            
            section_table = Table(section_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch])
            section_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E5E7EB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#111827')),
                ('FONTWEIGHT', (0, 0), (-1, 0), 'BOLD'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#4B5563')),
                ('FONTWEIGHT', (0, 1), (-1, -1), 'NORMAL'),
                ('TEXTCOLOR', (3, 1), (3, -1), lambda r, c, new_v=None:
                 colors.red if (r < len(section_data) and c < len(section_data[r]) and section_data[r][c] == 'Yes') else
                 colors.green if (r < len(section_data) and c < len(section_data[r]) and section_data[r][c] == 'No') else colors.black)
            ]))
            
            elements.append(section_table)
            elements.append(Spacer(1, 12))
    
    # Network Indicators
    if (analysis_data['network_indicators']['ip_addresses'] or 
        analysis_data['network_indicators']['domains']):
        
        elements.append(Paragraph("Network Indicators", styles['Heading2']))
        
        # IP Addresses
        if analysis_data['network_indicators']['ip_addresses']:
            elements.append(Paragraph("IP Addresses", styles['Heading3']))
            ip_data = [[ip] for ip in analysis_data['network_indicators']['ip_addresses'][:10]]  # Limit to 10
            if len(analysis_data['network_indicators']['ip_addresses']) > 10:
                ip_data.append([f"... and {len(analysis_data['network_indicators']['ip_addresses']) - 10} more"])
            
            ip_table = Table(ip_data, colWidths=[5.5*inch])
            ip_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Courier'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#DC2626')),
            ]))
            
            elements.append(ip_table)
            elements.append(Spacer(1, 12))
        
        # Domains
        if analysis_data['network_indicators']['domains']:
            elements.append(Paragraph("Domains", styles['Heading3']))
            domain_data = [[domain] for domain in analysis_data['network_indicators']['domains'][:10]]  # Limit to 10
            if len(analysis_data['network_indicators']['domains']) > 10:
                domain_data.append([f"... and {len(analysis_data['network_indicators']['domains']) - 10} more"])
            
            domain_table = Table(domain_data, colWidths=[5.5*inch])
            domain_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Courier'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2563EB')),
            ]))
            
            elements.append(domain_table)
            elements.append(Spacer(1, 12))
    
    # ML Attribution Results
    if analysis_data.get('ml_prediction') and not analysis_data['ml_prediction'].get('error'):
        elements.append(Paragraph("Machine Learning Attribution", styles['Heading2']))
        
        ml_prediction = analysis_data['ml_prediction']
        threat_actor_info = ml_prediction.get('threat_actor_info', {})
        
        ml_data = [
            ["Predicted Threat Actor:", ml_prediction['threat_actor']],
            ["Confidence Score:", f"{ml_prediction['confidence']:.1%}"],
            ["Final Decision:", ml_prediction.get('final_decision', 'Unknown')],
            ["Rule-based Validation:", ml_prediction.get('rule_confidence', 'Unknown')]
        ]
        
        if threat_actor_info:
            ml_data.extend([
                ["Country:", threat_actor_info.get('country', 'Unknown')],
                ["Primary Targets:", ', '.join(threat_actor_info.get('targets', []))],
                ["Common Tactics:", ', '.join(threat_actor_info.get('tactics', []))]
            ])
        
        ml_table = Table(ml_data, colWidths=[2.5*inch, 3*inch])
        ml_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#4B5563')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
            ('FONTWEIGHT', (0, 0), (0, -1), 'BOLD'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E5E7EB')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#111827')),
            ('FONTWEIGHT', (0, 0), (-1, 0), 'BOLD'),
        ]))
        
        elements.append(ml_table)
        elements.append(Spacer(1, 12))
        
        # Prediction Probabilities
        if ml_prediction.get('probabilities'):
            elements.append(Paragraph("Prediction Probabilities", styles['Heading3']))
            prob_data = [["Threat Actor", "Probability"]]
            
            for actor, prob in ml_prediction['probabilities'].items():
                prob_data.append([actor, f"{prob:.1%}"])
            
            prob_table = Table(prob_data, colWidths=[2.5*inch, 3*inch])
            prob_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E5E7EB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#111827')),
                ('FONTWEIGHT', (0, 0), (-1, 0), 'BOLD'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ]))
            
            elements.append(prob_table)
            elements.append(Spacer(1, 12))
    
    # Build the PDF
    elements.append(Spacer(1, 12))
    
    # Add footer with links
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#666666'),
        spaceAfter=6
    )
    elements.append(Paragraph("For more information:", footer_style))
    elements.append(Paragraph("• MITRE ATT&CK: https://attack.mitre.org/", footer_style))
    elements.append(Paragraph("• VirusTotal: https://www.virustotal.com/", footer_style))
    elements.append(Paragraph("• CISA: https://www.cisa.gov/", footer_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("Report generated by Malware Forensic Analysis System - Educational Project", footer_style))
    
    doc.build(elements)