$(DEPS_DIR)/libtweetnacl.a: src/tweetnacl.c
	$(CC) $(CPPFLAGS) $(CFLAGS) src/tweetnacl.c -c -o $(DEPS_DIR)/tweetnacl.o
	$(AR) rcs $@ $(DEPS_DIR)/tweetnacl.o 
