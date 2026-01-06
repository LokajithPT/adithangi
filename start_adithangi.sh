#!/bin/bash

echo "🎮 =======================================🎮"
echo "🚀 ADITHANGI - TRAFFIC DIVERSION SYSTEM"
echo "🎮 =======================================🎮"
echo ""
echo "📡 Building the new traffic diversion game..."
echo ""

# Build everything
echo "🔧 Building C++ components..."
mkdir -p build
cd build
cmake ..
make

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi

echo ""
echo "🎮 Starting Traffic Diversion Game..."
echo ""

# Start AI server in background
echo "🧠 Starting AI Prediction Server (port 8080)..."
python3 ../ai_server.py &
AI_PID=$!
sleep 2

# Start game client in background  
echo "🎮 Starting Game Client (port 8081)..."
./bin/game_client &
GAME_PID=$!
sleep 2

# Start scanner in background
echo "📡 Starting Traffic Scanner (port 8080)..."
./bin/scanner &
SCANNER_PID=$!

echo ""
echo "🎯 ALL SYSTEMS RUNNING!"
echo "   🧠 AI Server: PID $AI_PID (port 8080)"
echo "   📡 Traffic Scanner: PID $SCANNER_PID (capturing packets)"
echo "   🎮 Game Client: PID $GAME_PID (port 8081)"
echo ""
echo "📊 Traffic Flow:"
echo "   Network Packets → Scanner → AI Server (8080) → Game Client (8081) → Display"
echo ""
echo "🎮 The game will detect port scans and show AI predictions!"
echo "⚡ Try running: nmap -sS localhost to trigger detection"
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
    
    if [ ! -z "$GAME_PID" ]; then
        kill $GAME_PID 2>/dev/null
        echo "🎮 Stopped Game Client"
    fi
    
    echo "✅ All systems stopped!"
    exit 0
}

# Set trap for Ctrl+C
trap cleanup INT TERM

# Wait for processes
wait