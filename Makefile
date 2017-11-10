CXX = g++
CXXFLAGS = 
LINKS = -lsqlite3 -lgcrypt -lsodium


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

libsodium_install:
	cd ~/workspace
	wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	tar -xvzf LATEST.tar.gz
	rm LATEST.tar.gz
	cd libsodium-stable/
	./configure 
	make && make check
	sudo make install
	
clean:
	rm -rf *.o *.~ mail

# a database scrub command would be nice
db_clean:
	