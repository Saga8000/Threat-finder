import os
import pefile
import magic
import hashlib
import math
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

def calculate_file_hash(file_path: str, hash_type: str = 'sha256') -> str:
    """Calculate file hash using the specified algorithm."""
    hash_func = getattr(hashlib, hash_type)()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def calculate_entropy(data: bytes) -> float:
    """Calculate the entropy of a byte sequence."""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    seen = dict(((x, 0) for x in range(256)))
    
    for byte in data:
        seen[byte] += 1
    
    for count in seen.values():
        if count == 0:
            continue
        p = float(count) / length
        entropy -= p * math.log(p, 2)
    
    return entropy

def extract_pe_info(file_path: str) -> Dict[str, Any]:
    """Extract information from PE files."""
    try:
        pe = pefile.PE(file_path)
        pe_info = {
            'is_pe': True,
            'sections': [],
            'imports': set(),
            'exports': set(),
            'suspicious_imports': 0,
            'suspicious_sections': 0,
            'is_packed': False,
            'is_signed': False,
            'has_anti_debug': False,
            'has_vm_evasion': False
        }
        
        # Check sections
        suspicious_section_names = ['.vmp', '.packed', '.upx', '.upx0', '.upx1', '.upx2', 'UPX0', 'UPX1', 'UPX2']
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_entropy = section.get_entropy()
            section_info = {
                'name': section_name,
                'entropy': section_entropy,
                'size': section.SizeOfRawData,
                'is_suspicious': any(name in section_name for name in suspicious_section_names)
            }
            pe_info['sections'].append(section_info)
            
            # Check for packed sections
            if section_entropy > 7.0:  # High entropy may indicate packing
                pe_info['suspicious_sections'] += 1
                pe_info['is_packed'] = True
        
        # Check imports
        suspicious_imports = [
            'IsDebuggerPresent', 'OutputDebugString', 'FindWindow', 'GetTickCount',
            'GetTickCount64', 'QueryPerformanceCounter', 'rdtsc', 'cpuid', 'sldt',
            'strstr', 'lstrcmpi', 'lstrcmp', 'VirtualAlloc', 'VirtualProtect',
            'VirtualFree', 'CreateThread', 'CreateRemoteThread', 'WriteProcessMemory'
        ]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')
                            pe_info['imports'].add(f"{dll.lower()}.{imp_name}")
                            
                            # Check for suspicious imports
                            if imp_name in suspicious_imports:
                                pe_info['suspicious_imports'] += 1
                                
                                # Check for anti-debug techniques
                                if imp_name in ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']:
                                    pe_info['has_anti_debug'] = True
                                
                                # Check for VM/sandbox evasion
                                elif imp_name in ['GetTickCount', 'QueryPerformanceCounter', 'rdtsc']:
                                    pe_info['has_vm_evasion'] = True
                except:
                    continue
        
        # Check for digital signature
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            pe_info['is_signed'] = True
        
        return pe_info
    
    except Exception as e:
        return {
            'is_pe': False,
            'error': str(e)
        }

def analyze_file(file_path: str) -> Dict[str, Any]:
    """Analyze a file and extract features."""
    # Normalize the file path for cross-platform compatibility
    file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # Basic file info
    try:
        file_size = os.path.getsize(file_path)
    except OSError as e:
        raise OSError(f"Cannot get file size: {e}")

    # Get file type with error handling
    try:
        file_type = magic.from_file(file_path)
    except Exception as e:
        # Fallback if magic fails
        file_type = "Unknown"
        print(f"Warning: Could not determine file type: {e}")

    # Calculate hashes with error handling
    try:
        md5_hash = calculate_file_hash(file_path, 'md5')
        sha1_hash = calculate_file_hash(file_path, 'sha1')
        sha256_hash = calculate_file_hash(file_path, 'sha256')
    except Exception as e:
        raise OSError(f"Cannot calculate file hashes: {e}")
    
    # Extract PE info if it's a PE file
    pe_info = {}
    if 'PE32' in file_type or 'PE32+' in file_type:
        pe_info = extract_pe_info(file_path)
    
    # Calculate file entropy
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except IOError as e:
        raise IOError(f"Cannot read file: {e}")

    entropy = calculate_entropy(file_data)

    # Extract strings (basic implementation)
    try:
        strings = re.findall(b'[\\x20-\\x7E]{4,}', file_data)
        strings = [s.decode('utf-8', errors='ignore') for s in strings]
    except Exception as e:
        strings = []
        print(f"Warning: Could not extract strings: {e}")

    # Extract IPs and domains (basic regex, can be improved)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    ip_addresses = list(set(re.findall(ip_pattern, ' '.join(strings))))
    domains = list(set(re.findall(domain_pattern, ' '.join(strings))))
    
    # Prepare results
    result = {
        'file_info': {
            'filename': os.path.basename(file_path),
            'file_size': file_size,
            'file_type': file_type,
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
            'entropy': entropy,
            'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        'pe_info': pe_info,
        'network_indicators': {
            'ip_addresses': ip_addresses,
            'domains': domains
        },
        'strings': strings[:1000],  # Limit to first 1000 strings
        'is_suspicious': False,
        'threat_score': 0
    }
    
    # Calculate threat score (0-100)
    threat_score = 0
    
    # Increase score based on suspicious indicators
    if pe_info.get('is_packed', False):
        threat_score += 30
    if pe_info.get('has_anti_debug', False):
        threat_score += 20
    if pe_info.get('has_vm_evasion', False):
        threat_score += 20
    if ip_addresses:
        threat_score += 10
    if domains:
        threat_score += 10
    if entropy > 7.0:  # High entropy
        threat_score += 10
    
    # Cap at 100
    threat_score = min(100, threat_score)
    
    result['threat_score'] = threat_score
    result['is_suspicious'] = threat_score >= 50
    
    return result

def extract_features(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract features for ML model from analysis results."""
    pe_info = analysis_results.get('pe_info', {})
    
    features = {
        'suspicious_api_count': pe_info.get('suspicious_imports', 0),
        'has_ip': 1 if analysis_results['network_indicators']['ip_addresses'] else 0,
        'has_domain': 1 if analysis_results['network_indicators']['domains'] else 0,
        'is_packed': 1 if pe_info.get('is_packed', False) else 0,
        'is_signed': 1 if pe_info.get('is_signed', False) else 0,
        'has_anti_debug': 1 if pe_info.get('has_anti_debug', False) else 0,
        'has_vm_evasion': 1 if pe_info.get('has_vm_evasion', False) else 0,
        'entropy': analysis_results['file_info']['entropy'],
        'file_type': analysis_results['file_info']['file_type'].split(',')[0].lower(),
        'asn': 'AS0',  # Placeholder, would normally be looked up
        'target_sector': 'unknown'  # Placeholder
    }
    
    # Determine file type category
    file_type = analysis_results['file_info']['file_type'].lower()
    if 'executable' in file_type or 'dll' in file_type:
        features['file_type'] = 'executable'
    elif 'document' in file_type or 'office' in file_type:
        features['file_type'] = 'document'
    elif 'archive' in file_type or 'zip' in file_type or 'rar' in file_type:
        features['file_type'] = 'archive'
    else:
        features['file_type'] = 'other'
    
    return features

def analyze_url(url: str) -> Dict[str, Any]:
    """Analyze a URL for malicious patterns and indicators."""
    from urllib.parse import urlparse, parse_qs
    import re
    
    # Basic URL parsing
    try:
        parsed_url = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {e}")
    
    # Extract basic URL components
    url_info = {
        'original_url': url,
        'scheme': parsed_url.scheme,
        'netloc': parsed_url.netloc,
        'path': parsed_url.path,
        'query': parsed_url.query,
        'fragment': parsed_url.fragment,
        'hostname': parsed_url.hostname,
        'port': parsed_url.port,
        'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # URL length analysis
    url_length = len(url)
    domain_length = len(parsed_url.netloc) if parsed_url.netloc else 0
    path_length = len(parsed_url.path) if parsed_url.path else 0
    
    # Normalize URL for better detection
    normalized_url = url.lower()
    normalized_domain = (parsed_url.netloc or '').lower()
    
    # Expanded suspicious keywords and patterns (more targeted)
    suspicious_keywords = [
        'admin', 'login', 'password', 'bank', 'cryptocurrency', 'crypto', 'wallet', 
        'free', 'win', 'prize', 'secure', 'verify', 'account', 'update', 'confirm', 'alert',
        'suspicious', 'malware', 'virus', 'trojan', 'ransomware', 'phishing', 'scam',
        'check', 'validate', 'authentication', 'security', 'support', 'help', 'service',
        'exe', 'dll', 'bat', 'cmd', 'ps1', 'payload', 'inject', 'exploit', 'hack',
        'bypass', 'crack', 'keygen', 'patch', 'cheat', 'hacktool', 'backdoor',
        'recovery', 'recover', 'restore', 'unlock', 'access', 'portal', 'gateway',
        'billing', 'payment', 'invoice', 'refund', 'claim', 'bonus', 'reward'
    ]
    
    # Check for suspicious word combinations
    suspicious_combinations = [
        'secure login', 'account verify', 'password reset', 'bank login', 'paypal secure',
        'crypto wallet', 'free money', 'win prize', 'secure check', 'verify account',
        'login required', 'account suspended', 'security alert', 'update required',
        'confirm identity', 'validate account', 'suspicious activity', 'unusual login',
        'account recovery', 'password recovery', 'security update', 'account update',
        'payment required', 'billing update', 'invoice payment', 'refund claim'
    ]
    
    # Brand impersonation patterns (more specific and comprehensive)
    brand_impersonation = [
        'paypaI', 'pay-pal', 'paypal-secure', 'paypal-login', 'paypal-account', 'paypal-verify',
        'googIe', 'g00gle', 'google-drive', 'google-docs', 'google-login', 'google-secure',
        'micros0ft', 'microsoft-login', 'microsoft-account', 'microsoft-secure', 'microsoft-support',
        'appIe', 'apple-id', 'apple-login', 'apple-account', 'apple-verify',
        'amaz0n', 'amazon-login', 'amazon-account', 'amazon-secure', 'amazon-verify',
        'netfIix', 'netflix-account', 'netflix-login', 'netflix-verify',
        'faceb00k', 'facebook-security', 'facebook-login', 'facebook-verify',
        'twltter', 'twitter-login', 'twitter-verify',
        'instagrarn', 'instagram-password', 'instagram-login', 'instagram-verify',
        'Iinkedin', 'linkedin-login', 'linkedin-verify',
        'y0utube', 'youtube-login', 'youtube-verify'
    ]
    
    # Suspicious patterns detection
    suspicious_indicators = {
        'has_ip_in_domain': bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', parsed_url.netloc or '')),
        'has_suspicious_tld': parsed_url.netloc and any(parsed_url.netloc.lower().endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.cc', '.ws', '.buzz', '.info', '.online', '.site', '.tech', '.store', '.click', '.link', '.ru', '.cn', '.in', '.br', '.mx', '.ng', '.pk', '.bd', '.vn', '.th', '.id', '.my', '.ph', '.eg', '.ir', '.tr', '.za', '.co.ke', '.ma', '.tn', '.dz', '.ao', '.mz', '.bw', '.zw', '.zm', '.tz', '.ug', '.rw', '.bi', '.cd', '.cg', '.gq', '.ga', '.tg', '.bj', '.bf', '.ne', '.ml', '.sn', '.gm', '.gn', '.sl', '.lr', '.ci', '.gh', '.cv', '.st', '.km', '.mg', '.sc', '.mu', '.re', '.yt', '.mw', '.so', '.dj', '.ke', '.et', '.ss', '.sd', '.er', '.ye', '.om', '.ae', '.kw', '.qa', '.bh', '.jo', '.lb', '.sy', '.iq', '.ps', '.ye', '.af', '.tm', '.tj', '.kg', '.uz', '.mn', '.bt', '.np', '.lk', '.mv', '.bn', '.kh', '.la', '.mm', '.kp']),
        'has_long_subdomain': len((parsed_url.netloc or '').split('.')) > 3,
        'has_suspicious_words': any(word in normalized_url for word in suspicious_keywords),
        'has_suspicious_combinations': any(combination in normalized_url for combination in suspicious_combinations),
        'has_brand_impersonation': any(brand in url.lower() for brand in brand_impersonation),
        'has_encoded_chars': '%' in url,
        'has_at_symbol': '@' in url,
        'has_double_slash': '//' in parsed_url.path if parsed_url.path else False,
        'has_suspicious_ports': parsed_url.port and parsed_url.port not in [80, 443, 8080, 8443],
        'url_length_suspicious': url_length > 100,
        'domain_length_suspicious': domain_length > 50,
        'has_query_params': bool(parsed_url.query),
        'query_param_count': len(parse_qs(parsed_url.query)) if parsed_url.query else 0,
        'has_hyphen_in_domain': '-' in (parsed_url.netloc or ''),
        'has_multiple_hyphens': (parsed_url.netloc or '').count('-') > 2,
        'has_numbers_in_domain': bool(re.search(r'\d', parsed_url.netloc or '')),
        'domain_entropy_high': False,  # Will calculate below
        'is_shortened_url': parsed_url.netloc and any(shortener in parsed_url.netloc for shortener in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'adf.ly', 'is.gd', 'tiny.cc', 'cli.gs', 'su.pr', 'wp.me']),
        'has_suspicious_path': parsed_url.path and any(suspicious in parsed_url.path.lower() for suspicious in ['/admin/', '/login/', '/password/', '/secure/', '/verify/', '/exe', '/dll', '/bat', '/cmd', '/ps1'])
    }
    
    # Calculate domain entropy (measure of randomness)
    if parsed_url.netloc:
        domain_bytes = parsed_url.netloc.encode('utf-8')
        domain_entropy = calculate_entropy(domain_bytes)
        suspicious_indicators['domain_entropy_high'] = domain_entropy > 4.0  # Increased threshold
    
    # Calculate threat score for URL
    threat_score = 0
    if suspicious_indicators['has_ip_in_domain']: threat_score += 25
    if suspicious_indicators['has_suspicious_tld']: threat_score += 20
    if suspicious_indicators['has_long_subdomain']: threat_score += 15
    if suspicious_indicators['has_suspicious_words']: 
        threat_score += 15
        # Bonus for multiple suspicious words
        word_count = sum(1 for word in suspicious_keywords if word in normalized_url)
        if word_count > 1: threat_score += 10
    if suspicious_indicators['has_suspicious_combinations']: threat_score += 25
    if suspicious_indicators['has_brand_impersonation']: threat_score += 30
    if suspicious_indicators['has_encoded_chars']: threat_score += 10
    if suspicious_indicators['has_at_symbol']: threat_score += 20
    if suspicious_indicators['has_double_slash']: threat_score += 15
    if suspicious_indicators['has_suspicious_ports']: threat_score += 10
    if suspicious_indicators['url_length_suspicious']: threat_score += 10
    if suspicious_indicators['domain_length_suspicious']: threat_score += 10
    if suspicious_indicators['query_param_count'] > 5: threat_score += 15
    if suspicious_indicators['has_hyphen_in_domain']: threat_score += 3
    if suspicious_indicators['has_multiple_hyphens']: threat_score += 5
    if suspicious_indicators['has_numbers_in_domain']: threat_score += 5
    if suspicious_indicators['domain_entropy_high']: threat_score += 10
    if suspicious_indicators['is_shortened_url']: threat_score += 20
    if suspicious_indicators['has_suspicious_path']: threat_score += 20
    
    threat_score = min(100, threat_score)
    
    # Extract potential IOCs from URL
    ip_addresses = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url)
    domains = []
    if parsed_url.hostname and not suspicious_indicators['has_ip_in_domain']:
        domains = [parsed_url.hostname]
    
    # Prepare url_features for template compatibility
    url_features = {
        'suspicious_patterns': [],
        'has_ip': suspicious_indicators['has_ip_in_domain'],
        'ip_address': ip_addresses[0] if ip_addresses else None,
        'special_chars_count': len(re.findall(r'[^a-zA-Z0-9./-]', url)),
        'subdomain_count': len((parsed_url.netloc or '').split('.')) - 2 if parsed_url.netloc and '.' in parsed_url.netloc else 0,
        'is_https': parsed_url.scheme == 'https',
        'query_params_count': suspicious_indicators['query_param_count']
    }
    
    # Add suspicious patterns
    if suspicious_indicators['has_ip_in_domain']:
        url_features['suspicious_patterns'].append('IP address in domain')
    if suspicious_indicators['has_suspicious_tld']:
        url_features['suspicious_patterns'].append('Suspicious TLD')
    if suspicious_indicators['has_long_subdomain']:
        url_features['suspicious_patterns'].append('Long subdomain chain')
    if suspicious_indicators['has_suspicious_words']:
        url_features['suspicious_patterns'].append('Suspicious keywords')
    if suspicious_indicators['has_suspicious_combinations']:
        url_features['suspicious_patterns'].append('Suspicious word combinations')
    if suspicious_indicators['has_brand_impersonation']:
        url_features['suspicious_patterns'].append('Brand impersonation')
    if suspicious_indicators['has_encoded_chars']:
        url_features['suspicious_patterns'].append('Encoded characters')
    if suspicious_indicators['has_at_symbol']:
        url_features['suspicious_patterns'].append('@ symbol in URL')
    if suspicious_indicators['has_double_slash']:
        url_features['suspicious_patterns'].append('Double slash in path')
    if suspicious_indicators['url_length_suspicious']:
        url_features['suspicious_patterns'].append('Unusually long URL')
    if suspicious_indicators['has_hyphen_in_domain']:
        url_features['suspicious_patterns'].append('Hyphen in domain')
    if suspicious_indicators['has_multiple_hyphens']:
        url_features['suspicious_patterns'].append('Multiple hyphens in domain')
    if suspicious_indicators['has_numbers_in_domain']:
        url_features['suspicious_patterns'].append('Numbers in domain')
    if suspicious_indicators['domain_entropy_high']:
        url_features['suspicious_patterns'].append('High entropy domain')
    if suspicious_indicators['is_shortened_url']:
        url_features['suspicious_patterns'].append('URL shortener detected')
    if suspicious_indicators['has_suspicious_path']:
        url_features['suspicious_patterns'].append('Suspicious path')
    
    # Prepare results
    result = {
        'url_info': url_info,
        'url_features': url_features,
        'suspicious_indicators': suspicious_indicators,  # Keep for backward compatibility
        'network_indicators': {
            'ip_addresses': list(set(ip_addresses)),
            'domains': domains
        },
        'threat_score': threat_score,
        'is_suspicious': threat_score >= 25,
        'url_length': url_length,
        'domain_length': domain_length,
        'path_length': path_length,
        'normalized_url': normalized_url
    }
    
    return result

def extract_url_features(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """Extract features from URL analysis for ML model."""
    url_info = analysis_results.get('url_info', {})
    suspicious_indicators = analysis_results.get('suspicious_indicators', {})
    network_indicators = analysis_results.get('network_indicators', {})

    features = {
        'suspicious_api_count': 0,  # URLs don't have APIs
        'has_ip': 1 if network_indicators.get('ip_addresses') else 0,
        'has_domain': 1 if network_indicators.get('domains') else 0,
        'is_packed': 0,  # Not applicable for URLs
        'is_signed': 0,  # Not applicable for URLs
        'has_anti_debug': 0,  # Not applicable for URLs
        'has_vm_evasion': 0,  # Not applicable for URLs
        'entropy': 0,  # Could calculate URL entropy if needed
        'file_type': 'url',  # Special type for URLs
        'asn': 'AS0',  # Placeholder - would need ASN lookup
        'target_sector': 'unknown'  # Placeholder
    }

    # Map URL suspicious indicators to ML features with proper weighting
    suspicious_score = 0

    # High-risk indicators (major suspicious factors)
    if suspicious_indicators.get('has_ip_in_domain'):
        suspicious_score += 25  # IP in domain is very suspicious
        features['has_ip'] = 1

    if suspicious_indicators.get('has_suspicious_tld'):
        suspicious_score += 20  # Suspicious TLD
        features['has_domain'] = 1  # Mark as having suspicious domain

    if suspicious_indicators.get('has_brand_impersonation'):
        suspicious_score += 30  # Brand impersonation is highly malicious
        features['suspicious_api_count'] += 5

    if suspicious_indicators.get('has_suspicious_combinations'):
        suspicious_score += 25  # Suspicious word combinations
        features['suspicious_api_count'] += 4

    if suspicious_indicators.get('is_shortened_url'):
        suspicious_score += 20  # URL shorteners often hide malicious content
        features['has_anti_debug'] = 1  # Shorteners try to evade detection

    # Medium-risk indicators
    if suspicious_indicators.get('has_suspicious_words'):
        suspicious_score += 15
        features['suspicious_api_count'] += 2

    if suspicious_indicators.get('has_long_subdomain'):
        suspicious_score += 15
        features['has_vm_evasion'] = 1  # Long subdomains can evade detection

    if suspicious_indicators.get('domain_entropy_high'):
        suspicious_score += 10
        features['entropy'] = 1  # High entropy indicates randomness

    if suspicious_indicators.get('has_at_symbol'):
        suspicious_score += 20
        features['has_vm_evasion'] = 1

    if suspicious_indicators.get('has_double_slash'):
        suspicious_score += 15
        features['has_anti_debug'] = 1

    if suspicious_indicators.get('has_suspicious_ports'):
        suspicious_score += 10
        features['has_anti_debug'] = 1

    # Low-risk indicators (but still contribute)
    if suspicious_indicators.get('has_encoded_chars'):
        suspicious_score += 10
        features['has_anti_debug'] = 1

    if suspicious_indicators.get('url_length_suspicious'):
        suspicious_score += 5

    if suspicious_indicators.get('domain_length_suspicious'):
        suspicious_score += 5

    if suspicious_indicators.get('has_hyphen_in_domain'):
        suspicious_score += 3

    if suspicious_indicators.get('has_multiple_hyphens'):
        suspicious_score += 5

    if suspicious_indicators.get('has_numbers_in_domain'):
        suspicious_score += 5

    if suspicious_indicators.get('has_suspicious_path'):
        suspicious_score += 20
        features['suspicious_api_count'] += 3

    # Convert suspicious score to feature values
    # Scale the suspicious_api_count based on total suspicious score
    if suspicious_score >= 50:  # High suspicion
        features['suspicious_api_count'] = max(features['suspicious_api_count'], 6)
        features['is_packed'] = 1  # Treat as "packed" (obfuscated)
    elif suspicious_score >= 25:  # Medium suspicion
        features['suspicious_api_count'] = max(features['suspicious_api_count'], 3)
    elif suspicious_score >= 10:  # Low suspicion
        features['suspicious_api_count'] = max(features['suspicious_api_count'], 1)

    return features