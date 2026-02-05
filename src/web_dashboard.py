"""
Web Dashboard for Intrusion Detection System
Flask application with real-time monitoring interface
"""

from flask import Flask, render_template, jsonify
import os
from datetime import datetime
from realtime_detection import RealTimeIDS, generate_sample_traffic
import threading
import time

app = Flask(__name__)

# Global IDS instance
ids_instance = None
monitoring_active = False
monitoring_thread = None
latest_detections = []


def initialize_ids():
    """Initialize the IDS system"""
    global ids_instance
    try:
        ids_instance = RealTimeIDS(
            model_path='../models/best_ids_model.pkl',
            preprocessor_dir='../models'
        )
        return True
    except Exception as e:
        print(f"Error initializing IDS: {e}")
        return False


def background_monitor():
    """Background monitoring function"""
    global monitoring_active, latest_detections, ids_instance

    traffic = generate_sample_traffic(n_packets=1000, attack_rate=0.2)

    while monitoring_active:
        try:
            packet = next(traffic)
            result = ids_instance.detect(packet)

            # Keep only last 50 detections
            latest_detections.append(result)
            if len(latest_detections) > 50:
                latest_detections.pop(0)

            time.sleep(0.5)  # Simulate real-time delay

        except StopIteration:
            # Generate new traffic
            traffic = generate_sample_traffic(n_packets=1000, attack_rate=0.2)
        except Exception as e:
            print(f"Error in monitoring: {e}")
            break


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/status')
def status():
    """Get current IDS status"""
    if ids_instance is None:
        return jsonify({
            'initialized': False,
            'monitoring': False
        })

    return jsonify({
        'initialized': True,
        'monitoring': monitoring_active,
        'total_packets': ids_instance.total_packets,
        'attacks_detected': ids_instance.attacks_detected,
        'attack_rate': (
            (ids_instance.attacks_detected / ids_instance.total_packets * 100)
            if ids_instance.total_packets > 0 else 0
        )
    })


@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start monitoring network traffic"""
    global monitoring_active, monitoring_thread

    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=background_monitor, daemon=True)
        monitoring_thread.start()
        return jsonify({'success': True, 'message': 'Monitoring started'})
    else:
        return jsonify({'success': False, 'message': 'Monitoring already active'})


@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop monitoring network traffic"""
    global monitoring_active

    if monitoring_active:
        monitoring_active = False
        return jsonify({'success': True, 'message': 'Monitoring stopped'})
    else:
        return jsonify({'success': False, 'message': 'Monitoring not active'})


@app.route('/api/latest_detections')
def get_latest_detections():
    """Get latest detection results"""
    return jsonify(latest_detections[-20:])  # Return last 20


@app.route('/api/recent_attacks')
def get_recent_attacks():
    """Get recent attacks"""
    if ids_instance:
        attacks = ids_instance.get_recent_attacks(n=10)
        return jsonify(attacks)
    return jsonify([])


@app.route('/api/stats')
def get_stats():
    """Get detailed statistics"""
    if ids_instance is None:
        return jsonify({'error': 'IDS not initialized'})

    elapsed = (datetime.now() - ids_instance.start_time).total_seconds()

    return jsonify({
        'total_packets': ids_instance.total_packets,
        'attacks_detected': ids_instance.attacks_detected,
        'normal_traffic': ids_instance.total_packets - ids_instance.attacks_detected,
        'attack_rate': (
            (ids_instance.attacks_detected / ids_instance.total_packets * 100)
            if ids_instance.total_packets > 0 else 0
        ),
        'uptime': elapsed,
        'packets_per_second': ids_instance.total_packets / elapsed if elapsed > 0 else 0
    })


def create_dashboard_html():
    """Create the HTML dashboard template"""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intrusion Detection System Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }

        .controls {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }

        button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn-start {
            background: #10b981;
            color: white;
        }

        .btn-stop {
            background: #ef4444;
            color: white;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }

        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .stat-label {
            color: #666;
            font-size: 14px;
            margin-bottom: 5px;
        }

        .stat-value {
            color: #333;
            font-size: 32px;
            font-weight: bold;
        }

        .stat-unit {
            color: #999;
            font-size: 16px;
            margin-left: 5px;
        }

        .attack-rate {
            color: #ef4444;
        }

        .normal-rate {
            color: #10b981;
        }

        .detection-log {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        .log-header {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 15px;
            color: #333;
        }

        .log-container {
            max-height: 400px;
            overflow-y: auto;
            background: #f9fafb;
            padding: 15px;
            border-radius: 5px;
        }

        .log-entry {
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .log-normal {
            background: #d1fae5;
            border-left: 4px solid #10b981;
        }

        .log-attack {
            background: #fee2e2;
            border-left: 4px solid #ef4444;
        }

        .timestamp {
            color: #666;
            font-size: 12px;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-active {
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
        }

        .status-inactive {
            background: #6b7280;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .blinking {
            animation: blink 1s infinite;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Intrusion Detection System Dashboard</h1>
            <p style="color: #666; margin-top: 5px;">
                <span class="status-indicator" id="statusIndicator"></span>
                <span id="statusText">System Ready</span>
            </p>
            <div class="controls">
                <button class="btn-start" onclick="startMonitoring()" id="btnStart">Start Monitoring</button>
                <button class="btn-stop" onclick="stopMonitoring()" id="btnStop" disabled>Stop Monitoring</button>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Packets</div>
                <div class="stat-value" id="totalPackets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Attacks Detected</div>
                <div class="stat-value attack-rate" id="attacksDetected">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Normal Traffic</div>
                <div class="stat-value normal-rate" id="normalTraffic">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Attack Rate</div>
                <div class="stat-value" id="attackRate">0<span class="stat-unit">%</span></div>
            </div>
        </div>

        <div class="detection-log">
            <div class="log-header">📊 Real-Time Detection Log</div>
            <div class="log-container" id="logContainer">
                <div style="text-align: center; color: #999; padding: 20px;">
                    Waiting for monitoring to start...
                </div>
            </div>
        </div>
    </div>

    <script>
        let monitoringActive = false;

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    const indicator = document.getElementById('statusIndicator');
                    const statusText = document.getElementById('statusText');

                    if (data.monitoring) {
                        indicator.className = 'status-indicator status-active blinking';
                        statusText.textContent = 'Monitoring Active';
                        document.getElementById('btnStart').disabled = true;
                        document.getElementById('btnStop').disabled = false;
                    } else {
                        indicator.className = 'status-indicator status-inactive';
                        statusText.textContent = 'System Ready';
                        document.getElementById('btnStart').disabled = false;
                        document.getElementById('btnStop').disabled = true;
                    }

                    document.getElementById('totalPackets').textContent = data.total_packets || 0;
                    document.getElementById('attacksDetected').textContent = data.attacks_detected || 0;
                    document.getElementById('normalTraffic').textContent =
                        (data.total_packets - data.attacks_detected) || 0;
                    document.getElementById('attackRate').innerHTML =
                        (data.attack_rate || 0).toFixed(2) + '<span class="stat-unit">%</span>';
                });
        }

        function updateLog() {
            fetch('/api/latest_detections')
                .then(response => response.json())
                .then(data => {
                    const logContainer = document.getElementById('logContainer');

                    if (data.length === 0) return;

                    logContainer.innerHTML = '';

                    data.reverse().forEach(detection => {
                        const entry = document.createElement('div');
                        entry.className = detection.is_attack ? 'log-entry log-attack' : 'log-entry log-normal';

                        const status = detection.is_attack ? '🚨 ATTACK' : '✓ Normal';
                        const confidence = detection.confidence ?
                            ` (${(detection.confidence * 100).toFixed(1)}%)` : '';

                        entry.innerHTML = `
                            <div class="timestamp">${detection.timestamp}</div>
                            <div>Packet #${detection.packet_number}: ${status}${confidence}</div>
                        `;

                        logContainer.appendChild(entry);
                    });
                });
        }

        function startMonitoring() {
            fetch('/api/start_monitoring', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        monitoringActive = true;
                    }
                });
        }

        function stopMonitoring() {
            fetch('/api/stop_monitoring', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        monitoringActive = false;
                    }
                });
        }

        // Update every second
        setInterval(() => {
            updateStatus();
            updateLog();
        }, 1000);

        // Initial update
        updateStatus();
    </script>
</body>
</html>"""

    # Create templates directory
    os.makedirs('../templates', exist_ok=True)
    with open('../templates/dashboard.html', 'w') as f:
        f.write(html)


def main():
    """Main function to run the web dashboard"""
    print("=" * 60)
    print("INTRUSION DETECTION SYSTEM - WEB DASHBOARD")
    print("=" * 60)

    # Initialize IDS
    print("\nInitializing IDS...")
    if initialize_ids():
        print("✓ IDS initialized successfully")
    else:
        print("✗ Failed to initialize IDS")
        print("Please run train_model.py first to create the model")
        return

    # Create dashboard HTML
    create_dashboard_html()
    print("✓ Dashboard template created")

    # Run Flask app
    print("\n" + "=" * 60)
    print("Starting web server...")
    print("Dashboard available at: http://127.0.0.1:5000")
    print("Press CTRL+C to stop")
    print("=" * 60 + "\n")

    app.run(debug=False, host='0.0.0.0', port=5000)


if __name__ == "__main__":
    main()
