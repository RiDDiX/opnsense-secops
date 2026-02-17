"""
OPNsense Security Auditor - Web Dashboard
Flask-based web interface for managing scans and viewing results
"""
import os
import json
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from datetime import datetime, timedelta
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
        self.total_steps = 8
        self.step_number = 0
        self.started_at = None
        self.completed_at = None
        self.error = None
        self.cancel_requested = False
        self.logs = []  # Console log messages
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
            self.logs = []
            self._add_log('info', 'Security scan started')
    
    def _add_log(self, level: str, message: str):
        """Add a log message (must be called with lock held or from within locked method)"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.logs.append({
            'timestamp': timestamp,
            'level': level,
            'message': message
        })
        # Keep only last 100 messages
        if len(self.logs) > 100:
            self.logs = self.logs[-100:]
    
    def log(self, level: str, message: str):
        """Add a log message (thread-safe)"""
        with self.lock:
            self._add_log(level, message)
    
    def update(self, step_name: str, step_number: int):
        with self.lock:
            if self.cancel_requested:
                self.status = 'cancelled'
                self._add_log('warning', 'Scan cancelled by user')
                return False
            self.current_step = step_name
            self.step_number = step_number
            self.progress = int((step_number / self.total_steps) * 100)
            self._add_log('info', f'Step {step_number}/{self.total_steps}: {step_name}')
            return True
    
    def complete(self):
        with self.lock:
            self.status = 'completed'
            self.progress = 100
            self.current_step = 'Scan completed'
            self.completed_at = datetime.now().isoformat()
            self._add_log('success', 'Security scan completed successfully')
    
    def fail(self, error: str):
        with self.lock:
            self.status = 'failed'
            self.error = error
            self.completed_at = datetime.now().isoformat()
            self._add_log('error', f'Scan failed: {error}')
    
    def cancel(self):
        with self.lock:
            self.cancel_requested = True
            if self.status == 'running':
                self.status = 'cancelling'
                self._add_log('warning', 'Cancellation requested...')
    
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
                'error': self.error,
                'logs': self.logs.copy()
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
    """Main dashboard"""
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
                
                # Step 8: Generate reports
                if not scan_manager.update('Generating reports...', 8):
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


@app.route('/api/reports/history', methods=['GET'])
def get_scan_history():
    """Get scan history with scores for trend display"""
    try:
        history = []
        if not os.path.exists(REPORTS_DIR):
            return jsonify({'success': True, 'history': []})
        
        for filename in os.listdir(REPORTS_DIR):
            if filename.startswith('security_audit_') and filename.endswith('.json'):
                filepath = os.path.join(REPORTS_DIR, filename)
                try:
                    with open(filepath, 'r') as f:
                        report = json.load(f)
                    
                    summary = report.get('summary', {})
                    entry = {
                        'filename': filename,
                        'timestamp': report.get('scan_timestamp', ''),
                        'score': report.get('security_score', 0),
                        'grade': report.get('security_grade', 'F'),
                        'total_findings': summary.get('total_findings', 0),
                        'critical': summary.get('critical', 0),
                        'high': summary.get('high', 0),
                        'medium': summary.get('medium', 0),
                        'low': summary.get('low', 0),
                        'category_scores': calculate_category_scores(report)
                    }
                    history.append(entry)
                except Exception as e:
                    logger.debug(f"Skipping corrupt report {filename}: {e}")
        
        history.sort(key=lambda x: x['timestamp'])
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"Failed to get scan history: {e}")
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


@app.route('/api/reports/<filename>/html', methods=['GET'])
def download_html_report(filename):
    """Generate and download HTML report from JSON report"""
    try:
        json_path = os.path.join(REPORTS_DIR, filename)
        if not os.path.exists(json_path):
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        with open(json_path, 'r') as f:
            report_data = json.load(f)
        
        from src.report_generator import ReportGenerator
        generator = ReportGenerator()
        html_content = generator.generate_html_report(report_data)
        
        html_filename = filename.replace('.json', '.html')
        return Response(
            html_content,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment; filename={html_filename}'}
        )
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reports/clear', methods=['POST'])
def clear_scan_history():
    """Delete all scan reports to start fresh"""
    try:
        deleted = 0
        if os.path.exists(REPORTS_DIR):
            for filename in os.listdir(REPORTS_DIR):
                filepath = os.path.join(REPORTS_DIR, filename)
                if os.path.isfile(filepath) and filename.startswith('security_audit_'):
                    os.remove(filepath)
                    deleted += 1
        
        logger.info(f"Cleared {deleted} report files")
        return jsonify({
            'success': True,
            'message': f'{deleted} Reports gelöscht',
            'deleted': deleted
        })
    except Exception as e:
        logger.error(f"Failed to clear reports: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# === Scan Schedule ===
_schedule_file = os.path.join(CONFIG_DIR, 'schedule.json')
_schedule_timer = None

def _load_schedule():
    """Load schedule config from file"""
    if os.path.exists(_schedule_file):
        with open(_schedule_file, 'r') as f:
            return json.load(f)
    return {'enabled': False, 'interval_hours': 24, 'next_run': None}

def _save_schedule(schedule):
    """Save schedule config to file"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(_schedule_file, 'w') as f:
        json.dump(schedule, f)

def _run_scheduled_scan():
    """Execute a scheduled scan (same flow as manual scan)"""
    global scan_manager, _schedule_timer
    schedule = _load_schedule()
    if not schedule.get('enabled', False):
        return
    
    if scan_manager.status not in ('running', 'cancelling'):
        logger.info("Starting scheduled scan...")
        
        def run_scan():
            global scan_manager
            try:
                scan_manager.start()
                
                scan_manager.update('Validating configuration...', 1)
                auditor = SecurityAuditor()
                if not auditor.validate_configuration():
                    scan_manager.fail('Configuration validation failed')
                    return
                
                scan_manager.update('Connecting to OPNsense...', 2)
                if not auditor.initialize_client():
                    scan_manager.fail('Failed to connect to OPNsense')
                    return
                
                scan_manager.update('Initializing analyzers...', 3)
                auditor.initialize_analyzers()
                auditor.scan_manager = scan_manager
                
                results = auditor.run_audit()
                
                if scan_manager.is_cancelled():
                    scan_manager.status = 'cancelled'
                    return
                
                scan_manager.update('Generating reports...', 8)
                auditor.report_generator.generate_reports(results, REPORTS_DIR)
                scan_manager.complete()
                
            except Exception as e:
                logger.error(f"Scheduled scan failed: {e}", exc_info=True)
                scan_manager.fail(str(e))
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
    
    # Schedule next run
    _schedule_next_run()

def _schedule_next_run():
    """Schedule the next scan based on interval"""
    global _schedule_timer
    schedule = _load_schedule()
    if not schedule.get('enabled', False):
        if _schedule_timer:
            _schedule_timer.cancel()
            _schedule_timer = None
        return
    
    interval = max(1, schedule.get('interval_hours', 24)) * 3600
    next_run = (datetime.now() + timedelta(seconds=interval)).isoformat()
    schedule['next_run'] = next_run
    _save_schedule(schedule)
    
    if _schedule_timer:
        _schedule_timer.cancel()
    _schedule_timer = threading.Timer(interval, _run_scheduled_scan)
    _schedule_timer.daemon = True
    _schedule_timer.start()
    logger.info(f"Next scheduled scan in {schedule.get('interval_hours', 24)}h at {next_run}")


@app.route('/api/schedule', methods=['GET'])
def get_schedule():
    """Get current scan schedule"""
    schedule = _load_schedule()
    return jsonify({'success': True, 'schedule': schedule})


@app.route('/api/schedule', methods=['POST'])
def set_schedule():
    """Set scan schedule"""
    try:
        data = request.json
        schedule = _load_schedule()
        schedule['enabled'] = data.get('enabled', False)
        schedule['interval_hours'] = max(1, int(data.get('interval_hours', 24)))
        
        if schedule['enabled']:
            interval = schedule['interval_hours'] * 3600
            schedule['next_run'] = (datetime.now() + timedelta(seconds=interval)).isoformat()
        else:
            schedule['next_run'] = None
        
        _save_schedule(schedule)
        
        if schedule['enabled']:
            _schedule_next_run()
        else:
            global _schedule_timer
            if _schedule_timer:
                _schedule_timer.cancel()
                _schedule_timer = None
        
        return jsonify({
            'success': True,
            'message': f"Schedule {'aktiviert' if schedule['enabled'] else 'deaktiviert'}",
            'schedule': schedule
        })
    except Exception as e:
        logger.error(f"Failed to set schedule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ignore-list/add-finding', methods=['POST'])
def add_finding_to_ignore_list():
    """Add a finding to ignore list (auto-categorize based on finding type)"""
    try:
        data = request.json
        finding = data.get('finding', {})
        
        # Auto-detect category from finding structure
        if finding.get('rule_id') or finding.get('rule_description'):
            category = 'firewall_exceptions'
            item = {
                'rule_id': finding.get('rule_id', ''),
                'description': finding.get('rule_description', finding.get('issue', '')),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        elif finding.get('port') and (finding.get('host') or finding.get('wan_exposed')):
            category = 'port_exceptions'
            item = {
                'port': finding.get('port'),
                'host': finding.get('host', ''),
                'description': finding.get('issue', ''),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        elif finding.get('check') and ('dns' in finding.get('check', '') or 'unbound' in finding.get('check', '')):
            category = 'dns_exceptions'
            item = {
                'check': finding.get('check', ''),
                'description': finding.get('issue', ''),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        elif finding.get('vlan_id') is not None:
            category = 'vlan_exceptions'
            item = {
                'vlan_id': finding.get('vlan_id'),
                'description': finding.get('issue', ''),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        elif finding.get('cve_id'):
            category = 'vulnerability_exceptions'
            item = {
                'cve_id': finding.get('cve_id', ''),
                'description': finding.get('issue', ''),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        else:
            category = 'system_exceptions'
            item = {
                'check': finding.get('check', ''),
                'category': finding.get('category', ''),
                'description': finding.get('issue', ''),
                'reason': data.get('reason', 'Manuell ausgeschlossen')
            }
        
        config_loader = ConfigLoader(CONFIG_DIR)
        _, exceptions = config_loader.load_all()
        
        if category not in exceptions:
            exceptions[category] = []
        exceptions[category].append(item)
        
        import yaml
        exceptions_file = os.path.join(CONFIG_DIR, 'exceptions.yaml')
        with open(exceptions_file, 'w') as f:
            yaml.dump(exceptions, f, default_flow_style=False, allow_unicode=True)
        
        return jsonify({
            'success': True,
            'message': 'Finding zur Ausnahmeliste hinzugefügt',
            'category': category,
            'item': item
        })
    except Exception as e:
        logger.error(f"Failed to add finding to ignore list: {e}")
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
        
        # Debug: Log raw interface data structure
        for iface_name, iface_data in interfaces.items():
            logger.debug(f"Interface {iface_name}: {type(iface_data)} - keys: {list(iface_data.keys()) if isinstance(iface_data, dict) else 'N/A'}")
        
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
                # Handle case where iface_data is just a string (interface name)
                if isinstance(iface_data, str):
                    iface_data = {'descr': iface_data, 'if': iface_name}
                elif not isinstance(iface_data, dict):
                    continue
                
                # Skip loopback and system interfaces
                if iface_name in ['lo0', 'pflog0', 'pfsync0', 'enc0']:
                    continue
                
                # Skip VLAN sub-interfaces (will be added from vlans list)
                if '.' in iface_name and iface_name in vlan_interfaces:
                    continue
                
                descr = iface_data.get('descr', iface_data.get('description', iface_name))
                
                # Determine type - only set if clearly identifiable
                detected_type = None
                name_lower = (descr or iface_name).lower()
                if 'wan' in name_lower or 'pppoe' in name_lower or iface_name.lower() == 'wan':
                    detected_type = 'wan'
                elif 'lan' in name_lower or iface_name.lower() == 'lan':
                    detected_type = 'lan'
                elif 'opt' in iface_name.lower():
                    # OPTx interfaces - user should classify
                    detected_type = None
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
    'discovered_hosts': [],  # Live list of discovered IPs
    'logs': [],  # Console log messages
    'error': None,
    'started_at': None,
    'total_hosts': 0,
    'scanned_hosts': 0
}
internal_scan_lock = threading.Lock()

INTERNAL_SCAN_TIMEOUT = 1800  # 30 minutes timeout
MAX_INTERNAL_LOGS = 200

def internal_scan_log(level: str, message: str):
    """Add log message to internal scan state"""
    global internal_scan_state
    with internal_scan_lock:
        timestamp = datetime.now().strftime('%H:%M:%S')
        internal_scan_state['logs'].append({
            'timestamp': timestamp,
            'level': level,
            'message': message
        })
        # Keep only last N messages
        if len(internal_scan_state['logs']) > MAX_INTERNAL_LOGS:
            internal_scan_state['logs'] = internal_scan_state['logs'][-MAX_INTERNAL_LOGS:]

def is_internal_scan_stuck():
    """Check if internal scan is stuck (running for too long)"""
    if internal_scan_state['status'] == 'running' and internal_scan_state.get('started_at'):
        elapsed = time.time() - internal_scan_state['started_at']
        return elapsed > INTERNAL_SCAN_TIMEOUT
    return False

@app.route('/api/scan/internal/cancel', methods=['POST'])
def cancel_internal_scan():
    """Cancel/reset internal scan state"""
    global internal_scan_state
    with internal_scan_lock:
        internal_scan_state = {
            'status': 'idle',
            'current_step': '',
            'devices': [],
            'discovered_hosts': [],
            'logs': [],
            'error': None,
            'started_at': None,
            'total_hosts': 0,
            'scanned_hosts': 0
        }
    return jsonify({'success': True, 'message': 'Internal scan cancelled'})

@app.route('/api/scan/internal', methods=['POST'])
def start_internal_scan():
    """Start internal network device scan"""
    global internal_scan_state
    
    # Check for stuck scan and auto-reset
    if internal_scan_state['status'] == 'running':
        if is_internal_scan_stuck():
            logger.warning("Internal scan was stuck, auto-resetting...")
            internal_scan_state['status'] = 'idle'
        else:
            return jsonify({'success': False, 'error': 'Scan already in progress. Use /api/scan/internal/cancel to force reset.'}), 400
    
    def run_internal_scan():
        global internal_scan_state
        try:
            import ipaddress
            import nmap
            
            with internal_scan_lock:
                internal_scan_state['status'] = 'running'
                internal_scan_state['current_step'] = 'Initializing...'
                internal_scan_state['devices'] = []
                internal_scan_state['discovered_hosts'] = []
                internal_scan_state['logs'] = []
                internal_scan_state['error'] = None
                internal_scan_state['started_at'] = time.time()
                internal_scan_state['total_hosts'] = 0
                internal_scan_state['scanned_hosts'] = 0
            
            internal_scan_log('info', '🚀 Starting internal network device scan...')
            
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
                        internal_scan_log('info', f'📋 Added network: {net["network"]} ({net.get("type", "unknown").upper()})')
            
            if not networks_to_scan:
                # Fallback to SCAN_NETWORK env var
                scan_net = os.getenv('SCAN_NETWORK', '192.168.1.0/24')
                networks_to_scan = [scan_net]
                internal_scan_log('warning', f'⚠️ No networks configured, using fallback: {scan_net}')
            
            internal_scan_state['current_step'] = f'Discovering hosts in {len(networks_to_scan)} networks...'
            internal_scan_log('info', f'🔍 Will scan {len(networks_to_scan)} network(s)')
            
            # Get DHCP/ARP data if possible
            dhcp_leases = []
            arp_table = []
            try:
                host = os.getenv('OPNSENSE_HOST')
                api_key = os.getenv('OPNSENSE_API_KEY')
                api_secret = os.getenv('OPNSENSE_API_SECRET')
                if all([host, api_key, api_secret]):
                    internal_scan_log('info', '📡 Fetching DHCP leases and ARP table from OPNsense...')
                    client = OPNsenseClient(host, api_key, api_secret)
                    dhcp_leases = client.get_dhcp_leases()
                    arp_table = client.get_arp_table()
                    internal_scan_log('success', f'✅ Got {len(dhcp_leases)} DHCP leases, {len(arp_table)} ARP entries')
            except Exception as e:
                internal_scan_log('warning', f'⚠️ Could not fetch DHCP/ARP data: {str(e)[:50]}')
            
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
            all_live_hosts = []
            
            # Phase 1: Host Discovery
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            internal_scan_log('info', '📡 PHASE 1: Host Discovery')
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            
            for net_idx, network in enumerate(networks_to_scan):
                internal_scan_state['current_step'] = f'Host discovery: {network}'
                internal_scan_log('info', f'🔎 Scanning network {net_idx+1}/{len(networks_to_scan)}: {network}')
                
                # First find live hosts with ping scan
                try:
                    nm.scan(hosts=network, arguments='-sn')
                    live_hosts = [h for h in nm.all_hosts() if is_private_ip(h)]
                    internal_scan_log('success', f'   ✅ Found {len(live_hosts)} live hosts in {network}')
                    
                    # Add discovered hosts to live list
                    for host_ip in live_hosts:
                        host_info = known_hosts.get(host_ip, {})
                        hostname = host_info.get('hostname', '')
                        display_name = f"{host_ip} ({hostname})" if hostname else host_ip
                        internal_scan_log('info', f'   📍 Discovered: {display_name}')
                        
                        with internal_scan_lock:
                            internal_scan_state['discovered_hosts'].append({
                                'ip': host_ip,
                                'hostname': hostname,
                                'network': network,
                                'status': 'pending'
                            })
                        all_live_hosts.append((host_ip, network))
                        
                except Exception as e:
                    internal_scan_log('error', f'   ❌ Host discovery failed: {str(e)[:50]}')
                    logger.error(f"Host discovery failed for {network}: {e}")
                    continue
            
            total_hosts = len(all_live_hosts)
            with internal_scan_lock:
                internal_scan_state['total_hosts'] = total_hosts
            
            internal_scan_log('info', f'📊 Total hosts to scan: {total_hosts}')
            
            # Phase 2: Port Scanning
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            internal_scan_log('info', '🔓 PHASE 2: Port Scanning (1-65535)')
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            
            for i, (host_ip, network) in enumerate(all_live_hosts):
                with internal_scan_lock:
                    internal_scan_state['scanned_hosts'] = i
                internal_scan_state['current_step'] = f'Scanning ports on {host_ip} ({i+1}/{total_hosts})'
                
                host_info = known_hosts.get(host_ip, {})
                hostname = host_info.get('hostname', '')
                display_name = f"{host_ip} ({hostname})" if hostname else host_ip
                
                internal_scan_log('info', f'🖥️  [{i+1}/{total_hosts}] Scanning: {display_name}')
                
                device = {
                    'ip': host_ip,
                    'mac': host_info.get('mac', ''),
                    'hostname': hostname,
                    'network': network,
                    'vlan': '',
                    'status': 'active',
                    'open_ports': [],
                    'services': {}
                }
                
                try:
                    # Full port scan (1-65535) with service detection
                    scan_start = time.time()
                    nm.scan(hosts=host_ip, arguments='-sS -p 1-65535 --min-rate=1000 -T4')
                    scan_duration = time.time() - scan_start
                    
                    if host_ip in nm.all_hosts():
                        # Get hostname from scan if not known
                        if not device['hostname'] and 'hostnames' in nm[host_ip]:
                            for h in nm[host_ip]['hostnames']:
                                if h.get('name'):
                                    device['hostname'] = h['name']
                                    break
                        
                        # Reverse DNS fallback
                        if not device['hostname']:
                            try:
                                import socket
                                resolved, _, _ = socket.gethostbyaddr(host_ip)
                                if resolved:
                                    device['hostname'] = resolved
                            except (socket.herror, socket.gaierror, OSError):
                                pass
                        
                        # Get MAC from scan if not known
                        if not device['mac'] and 'addresses' in nm[host_ip]:
                            device['mac'] = nm[host_ip]['addresses'].get('mac', '')
                        
                        # Get open ports
                        if 'tcp' in nm[host_ip]:
                            for port, port_info in nm[host_ip]['tcp'].items():
                                if port_info['state'] == 'open':
                                    device['open_ports'].append(port)
                                    service_name = port_info.get('name', 'unknown')
                                    device['services'][port] = service_name
                        
                        port_count = len(device['open_ports'])
                        if port_count > 0:
                            port_list = ', '.join(str(p) for p in sorted(device['open_ports'])[:10])
                            if port_count > 10:
                                port_list += f' (+{port_count - 10} more)'
                            internal_scan_log('success', f'   ✅ {port_count} open ports: {port_list} ({scan_duration:.1f}s)')
                        else:
                            internal_scan_log('info', f'   ℹ️  No open ports found ({scan_duration:.1f}s)')
                            
                except Exception as e:
                    internal_scan_log('error', f'   ❌ Scan failed: {str(e)[:50]}')
                    logger.error(f"Port scan failed for {host_ip}: {e}")
                
                devices.append(device)
                
                # Update devices list in real-time
                with internal_scan_lock:
                    internal_scan_state['devices'] = devices.copy()
                    internal_scan_state['scanned_hosts'] = i + 1
                    # Update discovered host status
                    for dh in internal_scan_state['discovered_hosts']:
                        if dh['ip'] == host_ip:
                            dh['status'] = 'completed'
                            dh['open_ports'] = len(device['open_ports'])
                            break
            
            # Scan complete
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            internal_scan_log('success', f'🎉 Scan completed! Found {len(devices)} devices')
            total_ports = sum(len(d['open_ports']) for d in devices)
            internal_scan_log('info', f'📊 Total open ports found: {total_ports}')
            internal_scan_log('info', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
            
            internal_scan_state['current_step'] = 'Scan completed'
            internal_scan_state['devices'] = devices
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


@app.route('/api/connection/test', methods=['POST'])
def test_connection():
    """Test OPNsense API connection"""
    try:
        data = request.json
        host = data.get('host', '')
        api_key = data.get('api_key', '')
        api_secret = data.get('api_secret', '')
        
        if not all([host, api_key, api_secret]):
            return jsonify({'success': False, 'error': 'Alle Felder müssen ausgefüllt sein'})
        
        client = OPNsenseClient(host, api_key, api_secret, verify_ssl=False)
        
        if client.test_connection():
            # Get version info
            sys_info = client.get_system_info()
            version = sys_info.get('product_version', sys_info.get('version', ''))
            return jsonify({
                'success': True,
                'version': version,
                'message': 'Verbindung erfolgreich'
            })
        else:
            return jsonify({'success': False, 'error': 'Verbindung fehlgeschlagen'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/results/latest', methods=['GET'])
def get_latest_results():
    """Get latest scan results with full details"""
    try:
        # Find latest report
        if not os.path.exists(REPORTS_DIR):
            return jsonify({'success': False, 'error': 'Keine Reports vorhanden'})
        
        json_files = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')]
        if not json_files:
            return jsonify({'success': False, 'error': 'Keine Reports vorhanden'})
        
        json_files.sort(reverse=True)
        latest = json_files[0]
        
        with open(os.path.join(REPORTS_DIR, latest), 'r') as f:
            results = json.load(f)
        
        # Calculate category scores
        results['category_scores'] = calculate_category_scores(results)
        
        # Add statistics if missing
        if 'statistics' not in results:
            results['statistics'] = {}
        
        return jsonify({
            'success': True,
            'results': results,
            'report_file': latest
        })
    except Exception as e:
        logger.error(f"Failed to get latest results: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


def calculate_category_scores(results):
    """Calculate security scores per category using weighted penalty system.
    
    Uses diminishing deductions so that many low-severity findings
    don't immediately drop a category to 0%. Each finding's impact
    decreases as more findings accumulate in the same category.
    """
    severity_weights = {'critical': 20, 'high': 12, 'medium': 5, 'low': 2}
    
    def calc_score(findings):
        if not findings:
            return 100
        total_penalty = 0
        for i, f in enumerate(findings):
            sev = (f.get('severity', '') or '').lower()
            weight = severity_weights.get(sev, 0)
            # Diminishing returns: each additional finding has less impact
            diminish = 1.0 / (1 + i * 0.3)
            total_penalty += weight * diminish
        return max(0, round(100 - total_penalty))
    
    # Split findings into categories
    # Port findings (WAN-exposed) count towards firewall score
    fw_findings = results.get('firewall_findings', []) + results.get('port_findings', [])
    dns_findings = results.get('dns_findings', [])
    sys_findings = []
    vpn_findings = []
    
    for f in results.get('system_findings', []):
        cat = (f.get('category', '') or '').lower()
        if 'vpn' in cat:
            vpn_findings.append(f)
        else:
            sys_findings.append(f)
    
    return {
        'firewall': calc_score(fw_findings),
        'dns': calc_score(dns_findings),
        'system': calc_score(sys_findings),
        'vpn': calc_score(vpn_findings)
    }


@app.route('/api/data/raw', methods=['GET'])
def get_raw_data():
    """Get raw OPNsense data (for debugging/verification)"""
    try:
        host = os.getenv('OPNSENSE_HOST', '')
        api_key = os.getenv('OPNSENSE_API_KEY', '')
        api_secret = os.getenv('OPNSENSE_API_SECRET', '')
        
        if not all([host, api_key, api_secret]):
            return jsonify({'success': False, 'error': 'OPNsense nicht konfiguriert'})
        
        client = OPNsenseClient(host, api_key, api_secret, verify_ssl=False)
        
        raw_data = {
            'firewall_rules': client.get_firewall_rules(),
            'nat_rules': client.get_nat_rules(),
            'interfaces': client.get_interfaces(),
            'dns_config': client.get_dns_config(),
            'system_config': client.get_system_config(),
            'vlans': client.get_vlans()
        }
        
        return jsonify({
            'success': True,
            'data': raw_data,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to get raw data: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Resume schedule if previously enabled
    _schedule_next_run()

    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
