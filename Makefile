CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
TARGET1 = honeypot
SOURCE1 = honeypot.cpp
TARGET2 = sniffer
SOURCE2 = sniffer.cpp

.PHONY: all clean run

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(SOURCE1)
	$(CXX) $(CXXFLAGS) -o $(TARGET1) $(SOURCE1) -pthread

$(TARGET2): $(SOURCE2)
	$(CXX) $(CXXFLAGS) -o $(TARGET2) $(SOURCE2)

clean:
	rm -f $(TARGET1) $(TARGET2) honeypot.log ids_events.json

run: $(TARGET1)
	sudo ./$(TARGET1)

install:
	@echo "To run honeypot on privileged ports (21, 22), use: sudo make run"
	@echo "Or to run on non-privileged ports for testing:"
	@echo "g++ -std=c++11 -DSSH_PORT=2222 -DFTP_PORT=2121 honeypot.cpp -o honeypot -pthread"