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

dump_users:
	sqlite3 $(DATABASE) "SELECT * FROM USERS"
	
dump_messages:
	sqlite3 $(DATABASE) "SELECT * FROM MESSAGES"

wipe_users:
	sqlite3 $(DATABASE) "DROP TABLE USERS;"
	sqlite3 $(DATABASE) "CREATE TABLE USERS(ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT UNIQUE NOT NULL, PASSWORD TEXT NOT NULL, ITER INTEGER NOT NULL);"
	
wipe_messages:
	sqlite3 $(DATABASE) "DROP TABLE MESSAGES;"
	sqlite3 $(DATABASE) "CREATE TABLE MESSAGES(ID INTEGER PRIMARY KEY AUTOINCREMENT, SENDER TEXT NOT NULL, RECIPIENT TEXT NOT NULL, READ INTEGER NOT NULL, MESSAGE TEXT NOT NULL, NONCE TEXT NOT NULL);"
