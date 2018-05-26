SRC=main.c
LIB=hello
OBJ=$(SRC:%.c=%.o)

all:libhello $(OBJ)
	$(CC)  $(OBJ) -L./hello -l$(LIB) -o main

libhello:
	$(MAKE) -C hello/

clean:
	-$(MAKE) -C hello/ clean
	-rm *.o main
