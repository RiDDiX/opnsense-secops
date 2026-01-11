"""
OPNsense Security Auditor - Web Dashboard
Flask-based web interface for managing scans and viewing results
"""
import os
import json
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime
import sys

from src.config_loader import ConfigLoader
from src.opnsense_client import OPNsenseClient
from src.main import SecurityAuditor
import threading
import time

app = Flask(__name__)

# Global scan state manager
class ScanManager:
    def __init__(self):
        self.status = 'idle'  # idle, running, completed, failed, cancelled
        self.progress = 0
        self.current_step = ''
        self.total_steps = 7
        self.step_number = 0
        self.started_at = None
        self.completed_at = None
        self.error = None
        self.cancel_requested = False
        self.lock = threading.Lock()
    
    def start(self):
        with self.lock:
            self.status = 'running'
            self.progress = 0
            self.current_step = 'Initializing...'
            self.step_number = 0
            self.started_at = datetime.now().isoformat()
            self.completed_at = None
            self.error = None
            self.cancel_requested = False
    
    def update(self, step_name: str, step_number: int):
        with self.lock:
            if self.cancel_requested:
                self.status = 'cancelled'
                return False
            self.current_step = step_name
            self.step_number = step_number
            self.progress = int((step_number / self.total_steps) * 100)
            return True
    
    def complete(self):
        with self.lock:
            self.status = 'completed'
            self.progress = 100
            self.current_step = 'Scan completed'
            self.completed_at = datetime.now().isoformat()
    
    def fail(self, error: str):
        with self.lock:
            self.status = 'failed'
            self.error = error
            self.completed_at = datetime.now().isoformat()
    
    def cancel(self):
        with self.lock:
            self.cancel_requested = True
            if self.status == 'running':
                self.status = 'cancelling'
    
    def get_status(self):
        with self.lock:
            return {
                'status': self.status,
                'progress': self.progress,
                'current_step': self.current_step,
                'step_number': self.step_number,
                'total_steps': self.total_steps,
                'started_at': self.started_at,
                'completed_at': self.completed_at,
                'error': self.error
            }
    
    def is_cancelled(self):
        with self.lock:
            return self.cancel_requested

scan_manager = ScanManager()
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
CONFIG_DIR = "/app/config"
REPORTS_DIR = "/app/reports"
TRANSLATIONS_FILE = os.path.join(os.path.dirname(__file__), 'translations.json')

# Load translations
with open(TRANSLATIONS_FILE, 'r', encoding='utf-8') as f:
    TRANSLATIONS = json.load(f)


def get_translation(key, lang='en'):
    """Get translation for a key"""
    return TRANSLATIONS.get(lang, {}).get(key, key)


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


def load_persistent_config():
    """Load persistent configuration from file, set environment variables"""
    config_file = os.path.join(CONFIG_DIR, 'opnsense.json')
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            # Set environment variables from saved config
            if config.get('host'):
                os.environ['OPNSENSE_HOST'] = config['host']
            if config.get('api_key'):
                os.environ['OPNSENSE_API_KEY'] = config['api_key']
            if config.get('api_secret'):
                os.environ['OPNSENSE_API_SECRET'] = config['api_secret']
            if config.get('scan_network'):
                os.environ['SCAN_NETWORK'] = config['scan_network']
            if config.get('additional_networks'):
                os.environ['ADDITIONAL_NETWORKS'] = config['additional_networks']
            logger.info("Loaded persistent configuration from opnsense.json")
            return config
        except Exception as e:
            logger.error(f"Failed to load persistent config: {e}")
    return {}

# Load persistent config at startup
_persistent_config = load_persistent_config()


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        config_loader = ConfigLoader(CONFIG_DIR)
        rules, exceptions = config_loader.load_all()

        # Load from persistent file first, then environment variables as fallback
        config_file = os.path.join(CONFIG_DIR, 'opnsense.json')
        saved_config = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                saved_config = json.load(f)

        opnsense_config = {
            'host': saved_config.get('host') or os.getenv('OPNSENSE_HOST', ''),
            'api_key': saved_config.get('api_key') or os.getenv('OPNSENSE_API_KEY', ''),
            'api_secret': saved_config.get('api_secret') or os.getenv('OPNSENSE_API_SECRET', ''),
            'scan_network': saved_config.get('scan_network') or os.getenv('SCAN_NETWORK', '192.168.1.0/24'),
            'additional_networks': saved_config.get('additional_networks') or os.getenv('ADDITIONAL_NETWORKS', '')
        }

        return jsonify({
            'success': True,
            'opnsense': opnsense_config,
            'exceptions': exceptions,
            'scan_options': config_loader.get_scan_options(),
            'report_options': config_loader.get_report_options()
        })
    except Exception as e:
        logger.error(f"Failed to get config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def save_config():
    """Save configuration persistently"""
    try:
        data = request.json
        opnsense_data = data.get('opnsense', {})

        # Save OPNsense config to persistent file
        config_file = os.path.join(CONFIG_DIR, 'opnsense.json')
        with open(config_file, 'w') as f:
            json.dump(opnsense_data, f, indent=2)

        # Update environment variables immediately
        if opnsense_data.get('host'):
            os.environ['OPNSENSE_HOST'] = opnsense_data['host']
        if opnsense_data.get('api_key'):
            os.environ['OPNSENSE_API_KEY'] = opnsense_data['api_key']
        if opnsense_data.get('api_secret'):
            os.environ['OPNSENSE_API_SECRET'] = opnsense_data['api_secret']
        if opnsense_data.get('scan_network'):
            os.environ['SCAN_NETWORK'] = opnsense_data['scan_network']
        if opnsense_data.get('additional_networks'):
            os.environ['ADDITIONAL_NETWORKS'] = opnsense_data['additional_networks']

        # Save exceptions
        if 'exceptions' in data:
            import yaml
            exceptions_file = os.path.join(CONFIG_DIR, 'exceptions.yaml')
            with open(exceptions_file, 'w') as f:
                yaml.dump(data['exceptions'], f, default_flow_style=False)

        logger.info("Configuration saved persistently")
        return jsonify({'success': True, 'message': 'Configuration saved'})
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    global scan_manager
    
    try:
        # Check if scan is already running
        current_status = scan_manager.get_status()
        if current_status['status'] == 'running':
            return jsonify({
                'success': False,
                'error': 'A scan is already in progress',
                'status': current_status
            }), 400

        def run_scan():
            global scan_manager
            try:
                scan_manager.start()
                
                # Step 1: Initialize
                if not scan_manager.update('Validating configuration...', 1):
                    return
                
                auditor = SecurityAuditor()
                if not auditor.validate_configuration():
                    scan_manager.fail('Configuration validation failed')
                    return
                
                # Step 2: Connect to OPNsense
                if not scan_manager.update('Connecting to OPNsense...', 2):
                    return
                
                if not auditor.initialize_client():
                    scan_manager.fail('Failed to connect to OPNsense')
                    return
                
                # Step 3: Initialize analyzers
                if not scan_manager.update('Initializing analyzers...', 3):
                    return
                
                auditor.initialize_analyzers()
                
                # Pass scan_manager to auditor for progress updates
                auditor.scan_manager = scan_manager
                
                # Step 4-6: Run audit (progress updated inside)
                results = auditor.run_audit()
                
                if scan_manager.is_cancelled():
                    scan_manager.status = 'cancelled'
                    return
                
                # Step 7: Generate reports
                if not scan_manager.update('Generating reports...', 7):
                    return
                
                report_files = auditor.report_generator.generate_reports(results, REPORTS_DIR)
                logger.info(f"Scan completed. Reports: {report_files}")
                
                scan_manager.complete()
                
            except Exception as e:
                logger.error(f"Scan failed: {e}", exc_info=True)
                scan_manager.fail(str(e))

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Scan started',
            'status': scan_manager.get_status()
        })
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get current scan status and progress"""
    global scan_manager
    return jsonify({
        'success': True,
        **scan_manager.get_status()
    })


@app.route('/api/scan/cancel', methods=['POST'])
def cancel_scan():
    """Cancel the running scan"""
    global scan_manager
    
    current_status = scan_manager.get_status()
    if current_status['status'] not in ['running', 'cancelling']:
        return jsonify({
            'success': False,
            'error': 'No scan is currently running'
        }), 400
    
    scan_manager.cancel()
    
    return jsonify({
        'success': True,
        'message': 'Scan cancellation requested',
        'status': scan_manager.get_status()
    })


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all available reports"""
    try:
        reports = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.startswith('security_audit_') and filename.endswith('.json'):
                filepath = os.path.join(REPORTS_DIR, filename)
                stat = os.stat(filepath)

                # Extract timestamp from filename
                timestamp_str = filename.replace('security_audit_', '').replace('.json', '')

                reports.append({
                    'filename': filename,
                    'timestamp': timestamp_str,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
                })

        # Sort by timestamp descending
        reports.sort(key=lambda x: x['timestamp'], reverse=True)

        return jsonify({
            'success': True,
            'reports': reports
        })
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename):
    """Get a specific report"""
    try:
        filepath = os.path.join(REPORTS_DIR, filename)

        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'Report not found'}), 404

        with open(filepath, 'r') as f:
            report_data = json.load(f)

        return jsonify({
            'success': True,
            'report': report_data
        })
    except Exception as e:
        logger.error(f"Failed to get report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/<filename>/download', methods=['GET'])
def download_report(filename):
    """Download a report file"""
    try:
        return send_from_directory(REPORTS_DIR, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Failed to download report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ignore-list', methods=['GET'])
def get_ignore_list():
    """Get current ignore list"""
    try:
        config_loader = ConfigLoader(CONFIG_DIR)
        _, exceptions = config_loader.load_all()

        ignore_list = {
            'ports': exceptions.get('port_exceptions', []),
            'firewall_rules': exceptions.get('firewall_exceptions', []),
            'dns': exceptions.get('dns_exceptions', []),
            'vlans': exceptions.get('vlan_exceptions', []),
            'hosts': exceptions.get('host_exceptions', [])
        }

        return jsonify({
            'success': True,
            'ignore_list': ignore_list
        })
    except Exception as e:
        logger.error(f"Failed to get ignore list: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ignore-list/add', methods=['POST'])
def add_to_ignore_list():
    """Add item to ignore list"""
    try:
        data = request.json
        category = data.get('category')  # ports, firewall_rules, dns, vlans, hosts
        item = data.get('item')

        config_loader = ConfigLoader(CONFIG_DIR)
        _, exceptions = config_loader.load_all()

        # Add to appropriate category
        category_map = {
            'ports': 'port_exceptions',
            'firewall_rules': 'firewall_exceptions',
            'dns': 'dns_exceptions',
            'vlans': 'vlan_exceptions',
            'hosts': 'host_exceptions'
        }

        if category in category_map:
            key = category_map[category]
            if key not in exceptions:
                exceptions[key] = []
            exceptions[key].append(item)

            # Save updated exceptions
            import yaml
            exceptions_file = os.path.join(CONFIG_DIR, 'exceptions.yaml')
            with open(exceptions_file, 'w') as f:
                yaml.dump(exceptions, f, default_flow_style=False)

            return jsonify({
                'success': True,
                'message': 'Item added to ignore list'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid category'
            }), 400

    except Exception as e:
        logger.error(f"Failed to add to ignore list: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ignore-list/remove', methods=['POST'])
def remove_from_ignore_list():
    """Remove item from ignore list"""
    try:
        data = request.json
        category = data.get('category')
        index = data.get('index')

        config_loader = ConfigLoader(CONFIG_DIR)
        _, exceptions = config_loader.load_all()

        category_map = {
            'ports': 'port_exceptions',
            'firewall_rules': 'firewall_exceptions',
            'dns': 'dns_exceptions',
            'vlans': 'vlan_exceptions',
            'hosts': 'host_exceptions'
        }

        if category in category_map:
            key = category_map[category]
            if key in exceptions and 0 <= index < len(exceptions[key]):
                exceptions[key].pop(index)

                # Save updated exceptions
                import yaml
                exceptions_file = os.path.join(CONFIG_DIR, 'exceptions.yaml')
                with open(exceptions_file, 'w') as f:
                    yaml.dump(exceptions, f, default_flow_style=False)

                return jsonify({
                    'success': True,
                    'message': 'Item removed from ignore list'
                })

        return jsonify({
            'success': False,
            'error': 'Item not found'
        }), 404

    except Exception as e:
        logger.error(f"Failed to remove from ignore list: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/translations/<lang>', methods=['GET'])
def get_translations(lang):
    """Get translations for a language"""
    try:
        if lang not in TRANSLATIONS:
            return jsonify({'success': False, 'error': 'Language not found'}), 404

        return jsonify({
            'success': True,
            'translations': TRANSLATIONS[lang]
        })
    except Exception as e:
        logger.error(f"Failed to get translations: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/optimal-config', methods=['GET'])
def get_optimal_config():
    """Get optimal security configuration recommendations"""
    try:
        from src.analyzers.optimal_config_generator import OptimalConfigGenerator
        generator = OptimalConfigGenerator()
        
        # Get latest report if available
        latest_report = None
        reports_list = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.startswith('security_audit_') and filename.endswith('.json'):
                reports_list.append(filename)
        
        if reports_list:
            reports_list.sort(reverse=True)
            filepath = os.path.join(REPORTS_DIR, reports_list[0])
            with open(filepath, 'r') as f:
                latest_report = json.load(f)
        
        if latest_report:
            recommendations = generator.generate_recommendations(latest_report)
        else:
            # Return default optimal config without score
            recommendations = {
                "security_score": None,
                "grade": "N/A",
                "optimal_config": generator._get_optimal_config(),
                "implementation_guide": generator._get_implementation_guide(),
                "message": "Run a scan to get personalized recommendations"
            }
        
        return jsonify({
            'success': True,
            'recommendations': recommendations
        })
    except Exception as e:
        logger.error(f"Failed to get optimal config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/security-score', methods=['GET'])
def get_security_score():
    """Get current security score from latest report"""
    try:
        # Find latest report
        reports_list = []
        for filename in os.listdir(REPORTS_DIR):
            if filename.startswith('security_audit_') and filename.endswith('.json'):
                reports_list.append(filename)
        
        if not reports_list:
            return jsonify({
                'success': True,
                'score': None,
                'grade': 'N/A',
                'message': 'No scans completed yet'
            })
        
        reports_list.sort(reverse=True)
        filepath = os.path.join(REPORTS_DIR, reports_list[0])
        
        with open(filepath, 'r') as f:
            report = json.load(f)
        
        return jsonify({
            'success': True,
            'score': report.get('security_score', 0),
            'grade': report.get('security_grade', 'F'),
            'summary': report.get('summary', {}),
            'priority_actions': report.get('priority_actions', [])[:5],
            'timestamp': report.get('scan_timestamp', '')
        })
    except Exception as e:
        logger.error(f"Failed to get security score: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/networks', methods=['GET'])
def get_available_networks():
    """Fetch available networks/interfaces from OPNsense"""
    try:
        host = os.getenv('OPNSENSE_HOST')
        api_key = os.getenv('OPNSENSE_API_KEY')
        api_secret = os.getenv('OPNSENSE_API_SECRET')
        
        if not all([host, api_key, api_secret]):
            return jsonify({
                'success': False,
                'error': 'OPNsense credentials not configured'
            }), 400
        
        client = OPNsenseClient(host, api_key, api_secret)
        
        # Get interfaces
        interfaces = client.get_interfaces()
        
        # Get VLANs
        vlans = client.get_vlans()
        
        # Build network list
        networks = []
        
        # Parse interfaces for networks
        if isinstance(interfaces, dict):
            for iface_name, iface_data in interfaces.items():
                if isinstance(iface_data, dict):
                    # Get IPv4 address/network
                    ipv4 = iface_data.get('ipv4', [])
                    if ipv4 and isinstance(ipv4, list):
                        for addr_info in ipv4:
                            if isinstance(addr_info, dict):
                                addr = addr_info.get('ipaddr', '')
                                subnet = addr_info.get('subnetbits', '24')
                                if addr and not addr.startswith('127.'):
                                    # Calculate network from address
                                    try:
                                        import ipaddress
                                        network = ipaddress.ip_network(f"{addr}/{subnet}", strict=False)
                                        networks.append({
                                            'name': iface_data.get('descr', iface_name),
                                            'interface': iface_name,
                                            'network': str(network),
                                            'type': 'interface',
                                            'enabled': iface_data.get('enable', '1') == '1'
                                        })
                                    except:
                                        pass
        
        # Add VLANs
        for vlan in vlans:
            vlan_id = vlan.get('vlanif', vlan.get('tag', ''))
            networks.append({
                'name': f"VLAN {vlan_id}" + (f" - {vlan.get('descr', '')}" if vlan.get('descr') else ''),
                'interface': vlan.get('if', ''),
                'vlan_id': vlan_id,
                'type': 'vlan',
                'enabled': True
            })
        
        return jsonify({
            'success': True,
            'networks': networks,
            'vlans': vlans,
            'interfaces': interfaces
        })
    except Exception as e:
        logger.error(f"Failed to fetch networks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config/networks', methods=['POST'])
def save_network_selection():
    """Save selected networks for scanning"""
    try:
        data = request.json
        selected_networks = data.get('networks', [])
        
        # Save to config file
        config_file = os.path.join(CONFIG_DIR, 'scan_networks.json')
        with open(config_file, 'w') as f:
            json.dump({'selected_networks': selected_networks}, f, indent=2)
        
        return jsonify({'success': True, 'message': 'Network selection saved'})
    except Exception as e:
        logger.error(f"Failed to save network selection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config/networks', methods=['GET'])
def get_network_selection():
    """Get selected networks for scanning"""
    try:
        config_file = os.path.join(CONFIG_DIR, 'scan_networks.json')
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
            return jsonify({'success': True, 'networks': config.get('selected_networks', [])})
        return jsonify({'success': True, 'networks': []})
    except Exception as e:
        logger.error(f"Failed to get network selection: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/networks/fetch', methods=['GET'])
def fetch_networks_from_opnsense():
    """Fetch and auto-classify networks from OPNsense"""
    try:
        import ipaddress
        
        host = os.getenv('OPNSENSE_HOST')
        api_key = os.getenv('OPNSENSE_API_KEY')
        api_secret = os.getenv('OPNSENSE_API_SECRET')
        
        if not all([host, api_key, api_secret]):
            return jsonify({
                'success': False,
                'error': 'OPNsense credentials not configured. Please save API settings first.'
            }), 400
        
        client = OPNsenseClient(host, api_key, api_secret)
        
        # Get interfaces and VLANs
        interfaces = client.get_interfaces()
        vlans = client.get_vlans()
        
        logger.info(f"Fetched interfaces: {list(interfaces.keys()) if isinstance(interfaces, dict) else 'none'}")
        logger.info(f"Fetched VLANs: {len(vlans) if vlans else 0}")
        
        networks = []
        vlan_interfaces = set()  # Track VLAN interface names to avoid duplicates
        
        # First, collect VLAN interface names
        for vlan in vlans:
            vlan_tag = vlan.get('tag', vlan.get('vlanif', ''))
            parent_if = vlan.get('if', '')
            if vlan_tag and parent_if:
                vlan_interfaces.add(f"{parent_if}.{vlan_tag}")
        
        # Parse ALL interfaces
        if isinstance(interfaces, dict):
            for iface_name, iface_data in interfaces.items():
                if not isinstance(iface_data, dict):
                    continue
                
                # Skip loopback and system interfaces
                if iface_name in ['lo0', 'pflog0', 'pfsync0', 'enc0']:
                    continue
                
                # Skip VLAN sub-interfaces (will be added from vlans list)
                if '.' in iface_name and iface_name in vlan_interfaces:
                    continue
                
                descr = iface_data.get('descr', iface_name)
                
                # Determine type - only set if clearly identifiable
                detected_type = None
                if 'wan' in descr.lower() or 'pppoe' in descr.lower() or iface_name.lower() == 'wan':
                    detected_type = 'wan'
                elif 'lan' in descr.lower() or iface_name.lower() == 'lan':
                    detected_type = 'lan'
                # Otherwise leave as None - user must choose
                
                # Get IPv4 address - handle multiple formats
                network_str = None
                gateway = iface_data.get('gateway', '')
                
                # Format 1: ipv4 as list of dicts
                ipv4 = iface_data.get('ipv4', [])
                if ipv4 and isinstance(ipv4, list):
                    for addr_info in ipv4:
                        if isinstance(addr_info, dict):
                            addr = addr_info.get('ipaddr', '')
                            subnet = addr_info.get('subnetbits', '24')
                            if addr and not addr.startswith('127.'):
                                try:
                                    net = ipaddress.ip_network(f"{addr}/{subnet}", strict=False)
                                    network_str = str(net)
                                    # Public IP = likely WAN
                                    if not net.is_private and detected_type is None:
                                        detected_type = 'wan'
                                except:
                                    pass
                
                # Format 2: Direct ipaddr field
                if not network_str:
                    addr = iface_data.get('ipaddr', '')
                    subnet = iface_data.get('subnet', '24')
                    if addr and not addr.startswith('127.'):
                        try:
                            net = ipaddress.ip_network(f"{addr}/{subnet}", strict=False)
                            network_str = str(net)
                            if not net.is_private and detected_type is None:
                                detected_type = 'wan'
                        except:
                            pass
                
                # Format 3: Check for 'addr' in status
                if not network_str and 'status' in iface_data:
                    status = iface_data.get('status', {})
                    if isinstance(status, dict):
                        addr = status.get('ipaddr', '')
                        subnet = status.get('subnet', '24')
                        if addr:
                            try:
                                net = ipaddress.ip_network(f"{addr}/{subnet}", strict=False)
                                network_str = str(net)
                            except:
                                pass
                
                # Include ALL interfaces (regardless of enabled status)
                networks.append({
                    'name': descr or iface_name,
                    'interface': iface_name,
                    'network': network_str,
                    'gateway': gateway,
                    'type': detected_type,  # None if not clearly identifiable
                    'vlan_tag': None,
                    'enabled': iface_data.get('enable', iface_data.get('enabled', '1')) in ['1', 1, True, 'true']
                })
        
        # Add VLANs
        for vlan in vlans:
            vlan_tag = vlan.get('tag', vlan.get('vlanif', ''))
            descr = vlan.get('descr', '')
            parent_if = vlan.get('if', '')
            
            networks.append({
                'name': f"VLAN {vlan_tag}" + (f" ({descr})" if descr else ''),
                'interface': f"{parent_if}.{vlan_tag}",
                'network': None,  # VLANs often don't have IP on firewall
                'gateway': None,
                'type': 'vlan',
                'vlan_tag': vlan_tag,
                'enabled': True
            })
        
        return jsonify({
            'success': True,
            'networks': networks
        })
    except Exception as e:
        logger.error(f"Failed to fetch networks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# Internal device scan state
internal_scan_state = {
    'status': 'idle',
    'current_step': '',
    'devices': [],
    'error': None
}

@app.route('/api/scan/internal', methods=['POST'])
def start_internal_scan():
    """Start internal network device scan"""
    global internal_scan_state
    
    if internal_scan_state['status'] == 'running':
        return jsonify({'success': False, 'error': 'Scan already in progress'}), 400
    
    def run_internal_scan():
        global internal_scan_state
        try:
            import ipaddress
            import nmap
            
            internal_scan_state['status'] = 'running'
            internal_scan_state['current_step'] = 'Initializing...'
            internal_scan_state['devices'] = []
            internal_scan_state['error'] = None
            
            # Load network config
            config_file = os.path.join(CONFIG_DIR, 'scan_networks.json')
            networks_to_scan = []
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                # Only scan LAN and VLAN networks (not WAN)
                for net in config.get('selected_networks', []):
                    if net.get('type') in ['lan', 'vlan'] and net.get('network'):
                        networks_to_scan.append(net['network'])
            
            if not networks_to_scan:
                # Fallback to SCAN_NETWORK env var
                scan_net = os.getenv('SCAN_NETWORK', '192.168.1.0/24')
                networks_to_scan = [scan_net]
            
            internal_scan_state['current_step'] = f'Discovering hosts in {len(networks_to_scan)} networks...'
            
            # Get DHCP/ARP data if possible
            dhcp_leases = []
            arp_table = []
            try:
                host = os.getenv('OPNSENSE_HOST')
                api_key = os.getenv('OPNSENSE_API_KEY')
                api_secret = os.getenv('OPNSENSE_API_SECRET')
                if all([host, api_key, api_secret]):
                    client = OPNsenseClient(host, api_key, api_secret)
                    dhcp_leases = client.get_dhcp_leases()
                    arp_table = client.get_arp_table()
            except:
                pass
            
            # Helper to check if IP is private
            def is_private_ip(ip_str):
                try:
                    ip = ipaddress.ip_address(ip_str)
                    return ip.is_private and not ip.is_loopback
                except:
                    return False
            
            # Collect all known hosts from DHCP and ARP
            known_hosts = {}
            for lease in dhcp_leases:
                ip = lease.get('address', lease.get('ip', ''))
                if ip and is_private_ip(ip):
                    known_hosts[ip] = {
                        'mac': lease.get('mac', ''),
                        'hostname': lease.get('hostname', ''),
                        'status': 'active' if lease.get('state') == 'active' else 'inactive'
                    }
            
            for arp in arp_table:
                ip = arp.get('ip', '')
                if ip and is_private_ip(ip):
                    if ip not in known_hosts:
                        known_hosts[ip] = {}
                    known_hosts[ip]['mac'] = arp.get('mac', known_hosts.get(ip, {}).get('mac', ''))
                    known_hosts[ip]['status'] = 'active'
            
            # Use nmap to discover live hosts and scan ALL ports
            nm = nmap.PortScanner()
            devices = []
            
            for network in networks_to_scan:
                internal_scan_state['current_step'] = f'Host discovery: {network}'
                
                # First find live hosts with ping scan
                try:
                    nm.scan(hosts=network, arguments='-sn')
                    live_hosts = [h for h in nm.all_hosts() if is_private_ip(h)]
                except Exception as e:
                    logger.error(f"Host discovery failed for {network}: {e}")
                    continue
                
                # Full port scan on each live host (1-65535)
                for i, host_ip in enumerate(live_hosts):
                    internal_scan_state['current_step'] = f'Scanning ports on {host_ip} ({i+1}/{len(live_hosts)})'
                    
                    host_info = known_hosts.get(host_ip, {})
                    device = {
                        'ip': host_ip,
                        'mac': host_info.get('mac', ''),
                        'hostname': host_info.get('hostname', ''),
                        'network': network,
                        'vlan': '',
                        'status': 'active',
                        'open_ports': [],
                        'services': {}
                    }
                    
                    try:
                        # Full port scan (1-65535) with service detection
                        nm.scan(hosts=host_ip, arguments='-sS -p 1-65535 --min-rate=1000 -T4')
                        
                        if host_ip in nm.all_hosts():
                            # Get hostname from scan if not known
                            if not device['hostname'] and 'hostnames' in nm[host_ip]:
                                for h in nm[host_ip]['hostnames']:
                                    if h.get('name'):
                                        device['hostname'] = h['name']
                                        break
                            
                            # Get MAC from scan if not known
                            if not device['mac'] and 'addresses' in nm[host_ip]:
                                device['mac'] = nm[host_ip]['addresses'].get('mac', '')
                            
                            # Get open ports
                            if 'tcp' in nm[host_ip]:
                                for port, port_info in nm[host_ip]['tcp'].items():
                                    if port_info['state'] == 'open':
                                        device['open_ports'].append(port)
                                        device['services'][port] = port_info.get('name', 'unknown')
                    except Exception as e:
                        logger.error(f"Port scan failed for {host_ip}: {e}")
                    
                    devices.append(device)
            
            internal_scan_state['current_step'] = 'Scan completed'
            internal_scan_state['devices'] = devices  # Already dicts
            internal_scan_state['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"Internal scan failed: {e}")
            internal_scan_state['status'] = 'failed'
            internal_scan_state['error'] = str(e)
    
    thread = threading.Thread(target=run_internal_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Internal scan started'})


@app.route('/api/scan/internal/status', methods=['GET'])
def get_internal_scan_status():
    """Get internal scan status and results"""
    global internal_scan_state
    return jsonify({
        'success': True,
        **internal_scan_state
    })


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
