#include <iostream>
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

int main() {
    cout << "Welcome to Gee-Mail. Enter r to register or l to login: ";
    string input;
    cin >> input;
    if (input[0] == 'R' || input[0] == 'r') {
        //register
    } else if (input[0] == 'L' || input[0] == 'l') {
        login();
    }
    
    //more stuff on the way
    
    return 0;
}