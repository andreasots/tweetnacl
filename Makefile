$(DEPS_DIR)/libtweetnacl.a: src/tweetnacl.c src/randombytes.c
	$(CC) $(CPPFLAGS) $(CFLAGS) src/tweetnacl.c -c -o $(DEPS_DIR)/tweetnacl.o
	$(CC) $(CPPFLAGS) $(CFLAGS) src/randombytes.c -c -o $(DEPS_DIR)/randombytes.o
	$(AR) rcs $@ $(DEPS_DIR)/tweetnacl.o 
