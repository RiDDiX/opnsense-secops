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

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config_loader import ConfigLoader
from opnsense_client import OPNsenseClient
from main import SecurityAuditor

app = Flask(__name__)
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


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        config_loader = ConfigLoader(CONFIG_DIR)
        rules, exceptions = config_loader.load_all()

        # Get environment variables
        opnsense_config = {
            'host': os.getenv('OPNSENSE_HOST', ''),
            'scan_network': os.getenv('SCAN_NETWORK', '192.168.1.0/24'),
            'additional_networks': os.getenv('ADDITIONAL_NETWORKS', '')
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
    """Save configuration"""
    try:
        data = request.json

        # Save OPNsense config to environment (would need .env update in production)
        # For now, we'll save to a temporary config file
        config_file = os.path.join(CONFIG_DIR, 'opnsense.json')
        with open(config_file, 'w') as f:
            json.dump(data.get('opnsense', {}), f, indent=2)

        # Save exceptions
        if 'exceptions' in data:
            import yaml
            exceptions_file = os.path.join(CONFIG_DIR, 'exceptions.yaml')
            with open(exceptions_file, 'w') as f:
                yaml.dump(data['exceptions'], f, default_flow_style=False)

        return jsonify({'success': True, 'message': 'Configuration saved'})
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        # Run scan in background (in production, use Celery or similar)
        import threading

        def run_scan():
            try:
                auditor = SecurityAuditor()
                if auditor.validate_configuration():
                    if auditor.initialize_client():
                        auditor.initialize_analyzers()
                        results = auditor.run_audit()

                        # Generate reports
                        report_files = auditor.report_generator.generate_reports(results, REPORTS_DIR)
                        logger.info(f"Scan completed. Reports: {report_files}")
            except Exception as e:
                logger.error(f"Scan failed: {e}", exc_info=True)

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return jsonify({
            'success': True,
            'message': 'Scan started',
            'status': 'running'
        })
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get scan status"""
    # TODO: Implement proper scan status tracking
    return jsonify({
        'success': True,
        'status': 'idle',
        'progress': 0
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
        from analyzers.optimal_config_generator import OptimalConfigGenerator
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


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
