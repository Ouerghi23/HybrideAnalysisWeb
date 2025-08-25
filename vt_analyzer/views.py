import re
import base64
import time
import requests
import logging
from django.shortcuts import render
from django.conf import settings
from django.contrib import messages
from .forms import AnalysisForm
from urllib.parse import quote
from ipaddress import ip_address
from collections import defaultdict

logger = logging.getLogger(__name__)

def get_vt_api_key():
    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    if not api_key:
        logger.error("VIRUSTOTAL_API_KEY not configured in settings")
        raise ValueError("VirusTotal API key not configured")
    return api_key

def get_otx_api_key():
    api_key = getattr(settings, 'OTX_API_KEY', None)
    if not api_key:
        logger.error("OTX_API_KEY not configured in settings")
        raise ValueError("OTX API key not configured")
    return api_key

def get_ipinfo_token():
    return getattr(settings, 'IPINFO_TOKEN', None)

def detect_input_type(value):
    if not value:
        return "unknown"

    value = value.strip()

    if re.match(r'^https?://', value):
        return "url"

    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, value):
        return "ip"

    if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
        return "hash"
    elif re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
        return "hash"
    elif re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
        return "hash"

    return "unknown"

def vt_scan_file(file):
    try:
        headers = {'x-apikey': get_vt_api_key()}
        with file.open('rb') as f:
            files = {'file': (file.name, f)}
            response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                files=files,
                headers=headers,
                timeout=30
            )

        if response.status_code == 200:
            data = response.json()
            analysis_id = data['data']['id']

            for _ in range(10):
                time.sleep(15)
                report_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers=headers,
                    timeout=30
                )
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    if report_data['data']['attributes']['status'] == 'completed':
                        return report_data
            return {'error': 'Analysis timeout'}
        else:
            return {'error': f'API error: {response.status_code}'}

    except Exception as e:
        logger.error(f"VT file scan error: {str(e)}")
        return {'error': str(e)}

def vt_scan_url(url):
    try:
        headers = {'x-apikey': get_vt_api_key()}
        requests.post(
            'https://www.virustotal.com/api/v3/urls',
            data={'url': url},
            headers=headers,
            timeout=30
        )

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        time.sleep(5)
        report_response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=30
        )
        return report_response.json() if report_response.status_code == 200 else {'error': f'API error: {report_response.status_code}'}
    except Exception as e:
        logger.error(f"VT URL scan error: {str(e)}")
        return {'error': str(e)}

def vt_scan_ip(ip):
    try:
        headers = {'x-apikey': get_vt_api_key()}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers=headers,
            timeout=30
        )
        return response.json() if response.status_code == 200 else {'error': f'API error: {response.status_code}'}
    except Exception as e:
        logger.error(f"VT IP scan error: {str(e)}")
        return {'error': str(e)}

def vt_scan_hash(hash_value):
    try:
        headers = {'x-apikey': get_vt_api_key()}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{hash_value}',
            headers=headers,
            timeout=30
        )
        return response.json() if response.status_code == 200 else {'error': f'API error: {response.status_code}'}
    except Exception as e:
        logger.error(f"VT hash scan error: {str(e)}")
        return {'error': str(e)}


def normalize_for_otx(url):
    return url.replace("http://", "").replace("https://", "").strip("/")

def otx_scan_url(url):
    try:
        headers = {'X-OTX-API-KEY': get_otx_api_key()}
        encoded_url = quote(normalize_for_otx(url), safe='')

        endpoints = ['general', 'url_list', 'malware', 'analysis', 'pulses']
        results = {}
        pulse_info = None

        for endpoint in endpoints:
            full_url = f'https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/{endpoint}'
            response = requests.get(full_url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json() or {}
                results[endpoint] = data
                if endpoint == 'general':
                    pulse_info = data.get('pulse_info', {})
            else:
                results[endpoint] = {'error': f'API error: {response.status_code}'}

        return {
            'pulse_info': pulse_info or {},
            'reputation': results.get('general', {}).get('reputation'),
            'pulses': (pulse_info or {}).get('pulses', []),
            'malware_families': list(set(
                mf for pulse in (pulse_info or {}).get('pulses', [])
                for mf in pulse.get('malware_families', [])
            )),
            'raw': results
        }
    except Exception as e:
        logger.error(f"OTX URL scan error: {str(e)}")
        return {'error': str(e)}

def otx_scan_ip(ip):
    try:
        headers = {'X-OTX-API-KEY': get_otx_api_key()}
        response = requests.get(
            f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            data = response.json() or {}
            pulse_info = data.get('pulse_info', {})
            pulse_count = pulse_info.get('count', 0)
            pulses = pulse_info.get('pulses', [])

      
            pulse_names = [p.get('name', '') for p in pulses[:3]]

           
            if pulse_count > 0:
                summary = f"⚠ Found in {pulse_count} pulses: {', '.join(pulse_names)}"
            else:
                summary = "✅ No pulses found for this indicator"

            return {
                'pulse_info': pulse_info,
                'pulse_count': pulse_count,
                'pulse_names': pulse_names,
                'summary': summary,
                'reputation': data.get('reputation'),
                'geo': data.get('geo', {}),
                'base_indicator': data.get('base_indicator', {})
            }
        return {'error': f'API error: {response.status_code}'}
    except Exception as e:
        logger.error(f"OTX IP scan error: {str(e)}")
        return {'error': str(e)}

def otx_scan_hash(hash_value):
    try:
        headers = {'X-OTX-API-KEY': get_otx_api_key()}
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general",
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'pulse_info': data.get('pulse_info', {}),
                'reputation': data.get('reputation'),
                'base_indicator': data.get('base_indicator', {}),
                'raw': data
            }
        return {'error': f'API error: {response.status_code}'}
    except Exception as e:
        logger.error(f"OTX hash scan error: {str(e)}")
        return {'error': str(e)}

def get_ip_info(ip):
    try:
        token = get_ipinfo_token()
        if not token:
            return None
        response = requests.get(
            f'https://ipinfo.io/{ip}?token={token}',
            timeout=10
        )
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        logger.error(f"IPInfo error: {str(e)}")
        return None

def analyze(request):
    result = None
    error_message = None
    engine_choice = 'vt'

    if request.method == 'POST':
        form = AnalysisForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                input_value = form.cleaned_data.get('input_value', '').strip()
                uploaded_file = form.cleaned_data.get('file')
                engine_choice = form.cleaned_data.get('engine_choice', 'vt')

                result = {
                    'type': None,
                    'engine': engine_choice,
                    'input': input_value,
                    'file_name': uploaded_file.name if uploaded_file else None
                }

                if uploaded_file:
                    result['type'] = 'file'
                elif input_value:
                    result['type'] = detect_input_type(input_value)
                else:
                    result['type'] = 'unknown'

                if result['type'] == 'unknown':
                    error_message = "Type d'entrée non reconnu"
                else:
                    if engine_choice == 'vt':
                        if uploaded_file:
                            vt_result = vt_scan_file(uploaded_file)
                        elif result['type'] == 'url':
                            vt_result = vt_scan_url(input_value)
                        elif result['type'] == 'ip':
                            vt_result = vt_scan_ip(input_value)
                        elif result['type'] == 'hash':
                            vt_result = vt_scan_hash(input_value)
                        else:
                            vt_result = {'error': 'Type non pris en charge par VirusTotal'}

                        if 'error' in vt_result:
                            error_message = vt_result['error']
                        else:
                            result['vt'] = vt_result

                    elif engine_choice == 'otx':
                        otx_result = None  
                        
                        if uploaded_file:
                            error_message = "OTX ne supporte pas l'analyse de fichiers"
                        elif result['type'] == 'url':
                            otx_result = otx_scan_url(input_value)
                        elif result['type'] == 'ip':
                            otx_result = otx_scan_ip(input_value)
                        elif result['type'] == 'hash':
                            otx_result = otx_scan_hash(input_value)
                        else:
                            otx_result = {'error': 'Type non pris en charge par OTX'}

                        if otx_result and 'error' in otx_result:
                            error_message = otx_result['error']
                        elif otx_result:
                            if result['type'] == 'ip':
                                result['otx'] = {
                                    'pulse_count': otx_result['pulse_count'],
                                    'pulse_names': otx_result['pulse_names'],
                                    'summary': otx_result['summary'],
                                    'reputation': otx_result.get('reputation'),
                                    'geo': otx_result.get('geo', {})
                                }
                            else:
                                result['otx'] = {
                                    'pulse_count': otx_result.get('pulse_info', {}).get('count', 0),
                                    'reputation': otx_result.get('reputation'),
                                    'pulses': otx_result.get('pulse_info', {}).get('pulses', [])[:3],
                                    'malware_families': list(set(
                                        mf for pulse in otx_result.get('pulse_info', {}).get('pulses', [])
                                        for mf in pulse.get('malware_families', [])
                                    ))[:5],
                                    'geo': None  
                                }

                    if result['type'] == 'ip':
                        result['ipinfo'] = get_ip_info(input_value)

            except Exception as e:
                logger.error(f"Analysis error: {str(e)}")
                error_message = f"Erreur d'analyse: {str(e)}"
        else:
            error_message = "Formulaire invalide"
    else:
        form = AnalysisForm()

    if error_message:
        messages.error(request, error_message)

    return render(request, 'analyze.html', {
        'form': form,
        'result': result,
        'error_message': error_message,
        'engine_choice': engine_choice
    })