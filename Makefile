CXXFLAGS=
LDLIBS=-lpcap -lpthread
TARGET=arp_spoof

all: $(TARGET)

debug: CXXFLAGS += -DDEBUG -g
debug: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
