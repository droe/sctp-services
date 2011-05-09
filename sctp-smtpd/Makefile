TARGET = sctp-smtpd

all: $(TARGET)

$(TARGET): $(TARGET).c ../*.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) *.o *.core *~

