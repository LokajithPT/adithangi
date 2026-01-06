#!/usr/bin/env python3

import socket
import json
import threading
import time
from datetime import datetime
import random


class ScanPredictor:
    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = True
        self.scan_history = []

    def predict_scan_type(self, scan_data):
        """Predict what kind of scan this is"""
        ports_touched = scan_data.get("ports_touched", 0)
        total_packets = scan_data.get("total_packets", 0)

        # Simple ML prediction logic
        if ports_touched > 100:
            return "MASS_PORT_SCAN", 0.95
        elif ports_touched > 50:
            return "AGGRESSIVE_SCAN", 0.85
        elif ports_touched > 20:
            return "NETWORK_DISCOVERY", 0.75
        elif ports_touched > 10:
            return "TARGETED_SCAN", 0.65
        elif ports_touched > 5:
            return "EXPLORATORY_SCAN", 0.55
        else:
            return "SUSPICIOUS_ACTIVITY", 0.45

    def predict_attacker_intent(self, scan_data):
        """Predict attacker intent"""
        ports_touched = scan_data.get("ports_touched", 0)

        if ports_touched > 50:
            return "HACKTOOL_AUTOMATED", "Likely using automated scanning tools"
        elif ports_touched > 20:
            return "RECONNAISSANCE", "Network mapping and service discovery"
        elif ports_touched > 10:
            return "TARGETED_ATTACK", "Specific target preparation"
        else:
            return "CASUAL_SCANNING", "Opportunistic scanning"

    def generate_response(self, scan_data):
        """Generate AI prediction response"""
        src_ip = scan_data.get("src_ip", "unknown")

        # Get predictions
        scan_type, confidence = self.predict_scan_type(scan_data)
        intent, description = self.predict_attacker_intent(scan_data)

        # Determine if malicious
        is_malicious = confidence > 0.7
        threat_level = (
            "HIGH" if confidence > 0.8 else "MEDIUM" if confidence > 0.6 else "LOW"
        )

        # Create response
        response = {
            "timestamp": datetime.now().isoformat(),
            "scan_data": scan_data,
            "prediction": {
                "scan_type": scan_type,
                "intent": intent,
                "intent_description": description,
                "confidence": confidence,
                "threat_level": threat_level,
                "is_malicious": is_malicious,
            },
            "game_response": self.generate_game_response(
                is_malicious, src_ip, scan_type
            ),
        }

        return response

    def generate_game_response(self, is_malicious, src_ip, scan_type):
        """Generate in-game response to send back to C++"""
        if is_malicious:
            responses = [
                f"🎮 GAME ALERT: {src_ip} is {scan_type}! Initiating counter-measures...",
                f"🛡️ DEFENSE MODE: Scanning attacker {src_ip} for vulnerabilities...",
                f"⚔️ COUNTER-SCAN: Launching port scan probe against {src_ip}...",
                f"🔒 LOCKDOWN: Port scan detected from {src_ip} - activating shields!",
                f"💥 RETALIATION: Scan detected! Probing {src_ip} for open ports...",
            ]
        else:
            responses = [
                f"🔍 Monitoring: {src_ip} activity - low threat level",
                f"📡 Tracking: {src_ip} network behavior",
                f"👁️ Observation: Recording {src_ip} traffic patterns",
            ]

        return random.choice(responses)

    def send_to_cpp(self, cpp_socket, response):
        """Send prediction back to C++ scanner"""
        try:
            json_data = json.dumps(response)
            msg_len = len(json_data).to_bytes(4, byteorder="big")

            cpp_socket.send(msg_len)
            cpp_socket.send(json_data.encode("utf-8"))
        except Exception as e:
            print(f"❌ Failed to send to C++: {e}")

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"🧠 AI Prediction Server listening on {self.host}:{self.port}")
        print("🎮 Ready for scan detection and game integration!")
        print("⚡ Waiting for scan data from C++ scanner...")

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"🔗 Connected to C++ scanner at {addr}")

                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                if self.running:
                    print(f"❌ Error accepting connection: {e}")

    def handle_client(self, client_socket, addr):
        while self.running:
            try:
                # Receive message length (4 bytes)
                len_data = client_socket.recv(4)
                if not len_data:
                    break

                msg_len = int.from_bytes(len_data, byteorder="big")

                # Receive actual message
                msg_data = b""
                while len(msg_data) < msg_len:
                    chunk = client_socket.recv(msg_len - len(msg_data))
                    if not chunk:
                        break
                    msg_data += chunk

                if len(msg_data) == msg_len:
                    scan_data = json.loads(msg_data.decode("utf-8"))
                    response = self.generate_response(scan_data)

                    # Display prediction
                    self.display_prediction(response)

                    # Send back to C++ for game display
                    self.send_to_cpp(client_socket, response)

            except Exception as e:
                print(f"❌ Error handling client {addr}: {e}")
                break

        client_socket.close()
        print(f"🔌 Disconnected from {addr}")

    def display_prediction(self, response):
        """Display AI prediction in console"""
        scan_data = response["scan_data"]
        prediction = response["prediction"]
        game_resp = response["game_response"]

        print(f"\n🧠 AI PREDICTION:")
        print(f"   🎯 Source IP: {scan_data['src_ip']}")
        print(f"   🔢 Ports Touched: {scan_data['ports_touched']}")
        print(f"   📊 Scan Type: {prediction['scan_type']}")
        print(f"   🎭 Intent: {prediction['intent']}")
        print(f"   📝 Description: {prediction['intent_description']}")
        print(f"   🔥 Confidence: {prediction['confidence']:.2f}")
        print(f"   ⚠️ Threat Level: {prediction['threat_level']}")
        print(f"   🚨 Malicious: {'YES' if prediction['is_malicious'] else 'NO'}")
        print(f"   🎮 Game Response: {game_resp}")
        print("=" * 60)

    def stop(self):
        self.running = False
        self.server_socket.close()


if __name__ == "__main__":
    ai_server = ScanPredictor()

    try:
        ai_server.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down AI Prediction Server...")
        ai_server.stop()
