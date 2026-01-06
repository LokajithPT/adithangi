#!/bin/bash

echo "🎮 =======================================🎮"
echo "🚀 ADITHANGI - REAL HONEYPOT TRAP SYSTEM"
echo "🎮 =======================================🎮"
echo ""
echo "📡 DEPLOYING ON-DEMAND HONEYPOT SYSTEM..."
echo "🔥 IMMEDIATE DEPLOYMENT ON SCAN DETECTION!"
echo ""

# Build everything
echo "🔧 Building components..."
mkdir -p build
cd build
cmake .. && make

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "🎯 STARTING DEFENSE SYSTEM..."
echo ""

# Start AI server in background
echo "🧠 Starting AI Prediction Server (port 8080)..."
python3 ../ai_server.py &
AI_PID=$!
sleep 1

# Start scanner in background (this will detect scans and deploy honeypots)
echo "📡 Starting Traffic Scanner (captures packets and deploys honeypots on detection)..."
./bin/scanner &
SCANNER_PID=$!
sleep 1

echo ""
echo "🎯 ALL SYSTEMS RUNNING!"
echo "   🧠 AI Server: PID $AI_PID (port 8080)"
echo "   📡 Traffic Scanner: PID $SCANNER_PID (captures packets + deploys honeypots)"
echo ""
echo "🔥 HOW IT WORKS:"
echo "   1. Scanner monitors network traffic for port scans"
echo "   2. When scan detected → immediately deploys honeypots"
echo "   3. Attacker sees fake SSH (port 22) and FTP (port 21)" 
echo "   4. All attacker interactions logged to honeypot_attacks.json"
echo ""
echo "🍯 The moment someone scans your network → FAKE SERVICES APPEAR!"
echo "⚔️ No waiting period - instant deployment on scan detection!"
echo ""
echo "🎮 Try triggering: nmap -sS localhost"
echo "🎮 Or: telnet localhost 22"
echo "🎮 Or: ftp localhost"
echo ""
echo "Press Ctrl+C to stop everything..."
echo "🎮 =======================================🎮"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down ADITHANGI systems..."
    
    if [ ! -z "$AI_PID" ]; then
        kill $AI_PID 2>/dev/null
        echo "🧠 Stopped AI Server"
    fi
    
    if [ ! -z "$SCANNER_PID" ]; then
        kill $SCANNER_PID 2>/dev/null
        echo "📡 Stopped Traffic Scanner"
    fi
    
    # Stop any running honeypots
    pkill -f "python3.*fake_services.py" 2>/dev/null
    
    echo "✅ All systems stopped!"
    echo "📝 Check honeypot_attacks.json for captured intelligence!"
    exit 0
}

# Set trap for Ctrl+C
trap cleanup INT TERM

# Wait for processes
wait