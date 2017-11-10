CXX = g++
CXXFLAGS = 

DATABASE = secure.db

LINKS = -lsqlite3 -lsodium

all: run

mail.o: mail.cpp
	$(CXX) -c $(CXXFLAGS) mail.cpp

mail: mail.o
	$(CXX) -o mail mail.o $(LINKS) 

run: mail
	./mail

libsodium_install:
	cd ~/workspace
	wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	tar -xvzf LATEST.tar.gz
	rm LATEST.tar.gz
	cd libsodium-stable/
	./configure 
	make && make check
	sudo make install
	sudo ldconfig
	
clean:
	rm -rf *.o *.~ mail

# database commands

db_user_dump:
	sqlite3 $(DATABASE) < db_commands/user_dump.txt
	
db_message_dump:
	sqlite3 $(DATABASE) < db_commands/message_dump.txt

db_clean:
	