SRC=hello.c
OBJ=$(SRC:%.c=%.o)
all:$(OBJ)
	ar rcs libhello.a hello.o
clean:
	$(RM) *.a *.o
