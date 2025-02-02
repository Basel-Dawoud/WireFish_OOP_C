CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap

# Define the target
TARGET = wirefish

# Compile the code (using main.c and sniffer.c)
$(TARGET): main.c sniffer.c
	$(CC) $(CFLAGS) main.c sniffer.c -o $(TARGET) $(LIBS)

# Clean up generated files
clean:
	rm -f $(TARGET)

