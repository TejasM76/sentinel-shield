"""
Production SentinelShield Launcher
Proper port management and clean startup/shutdown
"""

import subprocess
import signal
import sys
import time
import os

class SentinelShieldLauncher:
    """Production launcher with proper port management"""

    def __init__(self):
        self.api_process = None
        self.dashboard_process = None
        self.api_port = 8000
        self.dashboard_port = 8504

    def check_port_free(self, port):
        """Check if port is free"""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return True
            except socket.error:
                return False

    def kill_process_on_port(self, port):
        """Kill any process using the specified port"""
        try:
            # Find process using the port
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True)
                        print(f"Killed process {pid} using port {port}")
                        time.sleep(1)
                        break
        except Exception as e:
            print(f"Warning: Could not kill process on port {port}: {e}")

    def start_api(self):
        """Start the API server"""
        print("Starting SentinelShield API Server...")

        # Ensure port is free
        if not self.check_port_free(self.api_port):
            print(f"Port {self.api_port} is in use, freeing it...")
            self.kill_process_on_port(self.api_port)

        try:
            # Start API using the main module
            self.api_process = subprocess.Popen([
                sys.executable, "-m", "app.main"
            ], cwd=os.path.dirname(__file__))

            print(f"✅ API Server started on port {self.api_port}")
            return True
        except Exception as e:
            print(f"❌ Failed to start API: {e}")
            return False

    def start_dashboard(self):
        """Start the dashboard"""
        print("🎨 Starting SentinelShield Dashboard...")

        # Ensure port is free
        if not self.check_port_free(self.dashboard_port):
            print(f"Port {self.dashboard_port} is in use, freeing it...")
            self.kill_process_on_port(self.dashboard_port)

        try:
            # Start dashboard using streamlit
            env = os.environ.copy()
            env['STREAMLIT_SERVER_PORT'] = str(self.dashboard_port)
            env['STREAMLIT_SERVER_HEADLESS'] = 'true'

            self.dashboard_process = subprocess.Popen([
                sys.executable, "-m", "streamlit", "run",
                "app/dashboard/app.py",
                "--server.port", str(self.dashboard_port),
                "--server.headless", "true"
            ], cwd=os.path.dirname(__file__), env=env)

            print(f"✅ Dashboard started on port {self.dashboard_port}")
            return True
        except Exception as e:
            print(f"❌ Failed to start dashboard: {e}")
            return False

    def stop_all(self):
        """Stop all services"""
        print("\n🛑 Stopping all services...")

        if self.api_process:
            try:
                self.api_process.terminate()
                self.api_process.wait(timeout=5)
                print("✅ API Server stopped")
            except Exception as e:
                print(f"Warning: Could not stop API gracefully: {e}")
                try:
                    self.api_process.kill()
                except:
                    pass

        if self.dashboard_process:
            try:
                self.dashboard_process.terminate()
                self.dashboard_process.wait(timeout=5)
                print("✅ Dashboard stopped")
            except Exception as e:
                print(f"Warning: Could not stop dashboard gracefully: {e}")
                try:
                    self.dashboard_process.kill()
                except:
                    pass

        # Final cleanup - kill any remaining processes on our ports
        self.kill_process_on_port(self.api_port)
        self.kill_process_on_port(self.dashboard_port)

    def run(self):
        """Run the complete system"""
        print("SentinelShield AI Security Platform - Production Launcher")
        print("="*60)

        # Setup signal handlers for clean shutdown
        def signal_handler(signum, frame):
            print(f"\nReceived signal {signum}, shutting down...")
            self.stop_all()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Start API
            if not self.start_api():
                print("❌ Failed to start API, aborting...")
                return

            # Wait a moment for API to start
            time.sleep(3)

            # Start Dashboard
            if not self.start_dashboard():
                print("❌ Failed to start dashboard, but API is running...")
                print("You can access the API directly at http://localhost:8000")

            print("\n🎉 SentinelShield Production System Running!")
            print("="*60)
            print("📡 API Server: http://localhost:8000")
            print("🎨 Dashboard: http://localhost:8504")
            print("🔍 Health Check: http://localhost:8000/health")
            print("🛡️ Threat Scan: POST http://localhost:8000/scan")
            print("="*60)
            print("Press Ctrl+C to stop all services cleanly")

            # Keep running until interrupted
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n👋 Shutdown requested by user")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
        finally:
            self.stop_all()

def main():
    """Main entry point"""
    launcher = SentinelShieldLauncher()
    launcher.run()

if __name__ == "__main__":
    main()
