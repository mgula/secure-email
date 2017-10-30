CXX = g++
CXXFLAGS = 
LINKS = -lsqlite3 -lgcrypt

all: run

mail.o: mail.cpp
	$(CXX) -c $(CXXFLAGS) mail.cpp

mail: mail.o
	$(CXX) -o mail mail.o $(LINKS)

run: mail
	./mail

gcrypt_install:
	sudo apt-get update
	sudo apt-get install libgcrypt20-dev

clean:
	rm -rf *.o *.~ mail

# a database scrub command would be nice
db_clean:
	