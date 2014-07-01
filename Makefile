target/libtweetnacl.a: src/tweetnacl.c
	mkdir target
	$(CC) $(CPPFLAGS) $(CFLAGS) src/tweetnacl.c -c -o target/tweetnacl.o
	$(AR) rcs $@ target/tweetnacl.o 
