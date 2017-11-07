#include <iostream>

#include <gcrypt.h>
#include <sqlite3.h>

using namespace std;

sqlite3* db;
const char* login_db_name = "login.db";

void login() {
    cout << "Please enter your username: ";
    string name;
    cin >> name;
    cout << "Please enter your password: ";
    string password;
    cin >> password;
    
    if (sqlite3_open(login_db_name, &db) == SQLITE_OK) {
        cout << "Opened db successfully\n";
    } else {
        cout << "Failed to open db\n";
        return;
    }
    
    //select from db with user and pass and etc
    
}

void register(){
    cout << "Enter a username: ";
    string name;
    cin >> name;
    cout << "Select a password: ";
    string password;
    cin >> password;
    cout << "Welcome new user!";
    return;
    
    //just a skeleton code for registering
    
}

void messages(){
    cout << "Hello! You have one new message from Boba! Would you like to read the message? (Y/N) ";
    string read;
    if(read[0] == 'Y' || read[0] == 'y'){
        read();
    }
    else if(read[0] == 'N' || read[0] == 'n'){
        cout << "You have no new messages!";

    }
    
    cout << "Would you like to write a message? (Y/N) ";
    string write;
    if(write[0] == 'Y' || write[0] == 'y'){
        write();
    }
    else{
        return;
    }
    
    //base for selecting to read/write a message
    
}

void read(){
    
    //code to read the message
    
}

void write(){
    cout << "Select a user recipient: ";
    string username;
    cin >> username;
    cout << "Type your message: ";
    string message;
    cin >> message;
    
    //start for writing messages
    
}


int main() {
    cout << "Welcome to Gee-Mail. Enter r to register or l to login: ";
    string input;
    cin >> input;
    if (input[0] == 'R' || input[0] == 'r') {
        register(); 
        //maybe have a new user log on after registering?
    } else if (input[0] == 'L' || input[0] == 'l') {
        login();
    }
    
    //more stuff on the way
    
    return 0;
}
