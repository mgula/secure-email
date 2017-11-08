#include <iostream>

#include <gcrypt.h>
#include <sqlite3.h>

using namespace std;

string current_user;

bool logged_in = false;

sqlite3* db;
const char* db_name = "secure.db";

void login() {
    cout << "Please enter your username: ";
    string name;
    cin >> name;
    cout << "Please enter your password: ";
    string password;
    cin >> password;
    
    if (sqlite3_open(db_name, &db) == SQLITE_OK) {
        cout << "Opened db successfully\n";
        logged_in = true;
        current_user = "jeff";
        
        
    } else {
        cout << "Failed to open db.\n";
        return;
    }
}

void register_user() {
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

void check_messages() {
    cout << "Hello! You have one new message from Boba! Would you like to read the message? (Y/N) ";
    string read;
    cin >> read;
    if(read[0] == 'Y' || read[0] == 'y'){
        //read();
    }
    else if(read[0] == 'N' || read[0] == 'n'){
        cout << "You have no new messages!";

    }
    
    cout << "Would you like to write a message? (Y/N) ";
    string write;
    cin >> write;
    if(write[0] == 'Y' || write[0] == 'y'){
        //write();
    }
    else{
        return;
    }
    
    //base for selecting to read/write a message
    
}

void read_message() {
    
    //code to read the message
    
}

void write_message() {
    cout << "Select a user recipient: ";
    string username;
    cin >> username;
    cout << "Type your message: ";
    string message;
    cin >> message;
    
    //start for writing messages
    
}

void help_info() {
    if (!logged_in) {
        cout << "\tr \t register a username" << endl;
        cout << "\tl \t login" << endl;
        cout << "\tq \t quit" << endl;
    } else {
        cout << "\tc \t check messages" << endl;
        cout << "\to \t open a message" << endl;
        cout << "\tw \t write a message" << endl;
        cout << "\tl \t logout" << endl;
        cout << "\tq \t quit" << endl;
    }
}

int main() {
    cout << "Welcome to Gee-Mail. Enter H for a list of commands. " << endl;
    string input;
    while (1) {
        cin >> input;
        
        /*Check for quit*/
        if (input[0] == 'Q' || input[0] == 'q') {
            //need safe quit method
            cout << "Exiting." << endl;
            break;
        }
        
        /*Check for help*/
        if (input[0] == 'H' || input[0] == 'h') {
            help_info();
            continue;
        }
        
        /*Login, if not logged in*/
        if (!logged_in) {
            if (input[0] == 'R' || input[0] == 'r') {
                //register
                cout << "Enter r to register or l to login: ";
            } else if (input[0] == 'L' || input[0] == 'l') {
                login();
                if (logged_in) {
                    cout << "Welcome, " << current_user << "." << endl;
                } else {
                    cout << "Enter r to register or l to login: " << endl;
                }
            } else {
                cout << "Command not recognized." << endl << "Enter r to register or l to login: ";
            }
        } else {
            //send messages, check messages, open message
        }
    }
    return 0;
}
