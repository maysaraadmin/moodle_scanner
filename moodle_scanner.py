#!/usr/bin/env python3
"""
Moodle Server Scanner

A utility to scan Moodle servers for open ports and gather system information.

Usage:
    python moodle_scanner.py <hostname> [--ports PORTS] [--timeout TIMEOUT]

Example:
    python moodle_scanner.py moodle.example.com --ports 80,443,3306 --timeout 2
"""

import socket
import ssl
import json
import argparse
import concurrent.futures
import requests
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

def get_ip_info(hostname):
    """Get IP address information for the given hostname."""
    try:
        ip = socket.gethostbyname(hostname)
        try:
            hostname_info = socket.gethostbyaddr(ip)
            return {
                'hostname': hostname,
                'ip': ip,
                'reverse_dns': hostname_info[0],
                'aliases': hostname_info[1],
                'is_private': ipaddress.ip_address(ip).is_private,
                'is_global': ipaddress.ip_address(ip).is_global
            }
        except socket.herror:
            return {
                'hostname': hostname,
                'ip': ip,
                'reverse_dns': 'Not found',
                'is_private': ipaddress.ip_address(ip).is_private,
                'is_global': ipaddress.ip_address(ip).is_global
            }
    except socket.gaierror as e:
        return {'error': f'Could not resolve hostname: {e}'}

def check_port(host, port, timeout=2):
    """Check if a port is open on the given host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            service = socket.getservbyport(port, 'tcp') if result == 0 else None
            return {
                'port': port,
                'status': 'open' if result == 0 else 'closed',
                'service': service
            }
    except (socket.timeout, socket.error, OSError) as e:
        return {
            'port': port,
            'status': 'filtered',
            'error': str(e)
        }

def get_ssl_info(host, port=443):
    """Get SSL certificate information."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                # Get certificate information
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'expires_in_days': (datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.now()).days
                }
    except Exception as e:
        return {'error': f'SSL error: {str(e)}'}

def get_moodle_info(url):
    """Get information about the Moodle instance."""
    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        # Try HTTPS first, fall back to HTTP if needed
        try:
            response = requests.get(f"{url.rstrip('/')}/lib/upgrade.txt", timeout=5, verify=False)
        except requests.exceptions.SSLError:
            url = url.replace('https://', 'http://')
            response = requests.get(f"{url.rstrip('/')}/lib/upgrade.txt", timeout=5)
            
        if response.status_code == 200:
            # Extract version information
            version_line = next((line for line in response.text.split('\n') if line.startswith('Version:')), None)
            version = version_line.split(':', 1)[1].strip() if version_line else 'Unknown'
            
            return {
                'version': version,
                'upgrade_url': f"{url}/admin/index.php"
            }
        return {'error': 'Could not determine Moodle version'}
    except requests.RequestException as e:
        return {'error': f'Failed to fetch Moodle info: {str(e)}'}

def scan_ports(host, ports, max_workers=100, timeout=2):
    """Scan multiple ports concurrently."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, host, port, timeout): port 
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            results.append(future.result())
    return sorted(results, key=lambda x: x['port'])

def main():
    parser = argparse.ArgumentParser(description='Moodle Server Scanner')
    parser.add_argument('hostname', help='Moodle server hostname or IP address')
    parser.add_argument('--ports', default='80,443,3306,5432,8080,8443',
                       help='Comma-separated list of ports to scan (default: 80,443,3306,5432,8080,8443)')
    parser.add_argument('--timeout', type=float, default=2,
                       help='Connection timeout in seconds (default: 2)')
    parser.add_argument('--output', help='Output file (JSON format)')
    
    args = parser.parse_args()
    
    try:
        # Parse ports
        ports = [int(p.strip()) for p in args.ports.split(',')]
        
        print(f"[+] Scanning {args.hostname}...\n")
        
        # Get IP information
        ip_info = get_ip_info(args.hostname)
        if 'error' in ip_info:
            print(f"[-] Error: {ip_info['error']}")
            return
            
        print("[*] Host Information:")
        print(f"    Hostname: {ip_info.get('hostname')}")
        print(f"    IP Address: {ip_info.get('ip')}")
        print(f"    Reverse DNS: {ip_info.get('reverse_dns', 'Not found')}")
        print(f"    Is Private: {ip_info.get('is_private')}")
        print(f"    Is Global: {ip_info.get('is_global')}\n")
        
        # Scan ports
        print(f"[*] Scanning {len(ports)} common Moodle ports...")
        results = scan_ports(ip_info['ip'], ports, timeout=args.timeout)
        
        open_ports = [r for r in results if r['status'] == 'open']
        
        print("\n[*] Open ports:")
        for port in open_ports:
            print(f"    {port['port']}/tcp : {port['service'] if port.get('service') else 'unknown service'}")
        
        # Initialize variables
        ssl_info = None
        moodle_info = None
        
        # Check for SSL if HTTPS is open
        if any(p['port'] == 443 for p in open_ports):
            print("\n[*] Checking SSL certificate...")
            ssl_info = get_ssl_info(ip_info['ip'])
            if 'error' not in ssl_info:
                print(f"    Issuer: {ssl_info.get('issuer', {}).get('O', 'Unknown')}")
                print(f"    Valid from: {ssl_info.get('not_before')}")
                print(f"    Expires: {ssl_info.get('not_after')} (in {ssl_info.get('expires_in_days', 0)} days)")
            else:
                print(f"    {ssl_info['error']}")
        
        # Try to get Moodle information if web ports are open
        web_ports = [80, 443, 8080, 8443]
        if any(p['port'] in web_ports and p['status'] == 'open' for p in results):
            print("\n[*] Attempting to identify Moodle version...")
            moodle_info = get_moodle_info(args.hostname)
            if 'version' in moodle_info:
                print(f"    Moodle version: {moodle_info['version']}")
                print(f"    Admin URL: {moodle_info['upgrade_url']}")
            elif 'error' in moodle_info:
                print(f"    {moodle_info['error']}")
            else:
                print("    Could not determine Moodle version")
        
        # Prepare output
        output = {
            'timestamp': datetime.now().isoformat(),
            'target': args.hostname,
            'ip_info': ip_info,
            'port_scan': results,
            'ssl_info': ssl_info,
            'moodle_info': moodle_info
        }
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(output, f, indent=2)
                print(f"\n[+] Results saved to {args.output}")
            except IOError as e:
                print(f"\n[-] Error saving results: {e}")
                
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[-] An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
