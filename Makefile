# Define variables
CC = gcc
CFLAGS = -lssl -lcrypto 
SOURCES = src/main.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = zefm

# Define targets and dependencies
all: $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CC) $(SOURCES) $(CFLAGS) -o $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE)
