CXX = g++
CXXFLAGS = 
LINKS = -lsqlite3

all: run

mail.o: mail.cpp
	$(CXX) -c $(CXXFLAGS) mail.cpp

mail: mail.o
	$(CXX) -o mail mail.o $(LINKS)

run: mail
	./mail

clean:
	rm -rf *.o *.~ mail

# a database scrub command would be nice
db_clean:
	