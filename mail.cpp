#include <iostream>
#include <string.h>
#include <sqlite3.h>
#include <stdio.h>
#include <sodium.h>

#define AMT_OPERATIONS 2<<22

using namespace std;

bool logged_in = false;
string current_user;

sqlite3* db;
const char* db_name = "secure.db";
sqlite3_stmt *stmt;
int rc;

/*Database interaction methods*/
bool open_db_connection();
bool close_db_connection();
void sql_stmt(const char* stmt);
bool prepare_statement(const char* query);
bool bind_text(int index, string text);
bool bind_text(int index, char* text, int len);
void encrypt(string, char*, unsigned int);
bool verify(string pass, char* hash);
bool check_existing(string user);
void print_bytes(const void *object, size_t size);

/*Methods that appear in main*/
void register_user();
void login();
void check_messages();
void read_message();
void write_message();
void help_info();

int main() {
    /*Check sodium status*/
    if (sodium_init() < 0) {
        printf("Sodium may not have been properly installed.\n");
        return 1;
    }
    
    /*Establish db connection*/
    if (!open_db_connection()) {
        return 1;
    }
    
    printf("Welcome to Gee-Mail. Enter H for a list of commands.\n");
    string input;

    while (1) {
        cin >> input;
        
        /*Check for quit*/
        if (input[0] == 'Q' || input[0] == 'q') {
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
                register_user();
                printf("Enter r to register or l to login.\n");
            } else if (input[0] == 'L' || input[0] == 'l') {
                login();
                if (logged_in) {
                    printf("Welcome, %s.\n", current_user.c_str());
                } else {
                    printf("Enter r to register or l to login.\n");
                }
            } else {
                printf("Command not recognized.\n Enter r to register or l to login.\n");
            }
        } else {
            //send messages, check messages, open message
        }
    }
    
    printf("Closing Gee-Mail.\n");
    close_db_connection();
    return 0;
}

bool open_db_connection() {
    sqlite3_open(db_name, &db);

    if (db == 0) {
        printf("\nCould not open database.\n");
        return false;
    }
    return true;
}

bool close_db_connection() {
    sqlite3_close(db);

    if (db == 0) {
        printf("\nCould not close database.\n");
        return false;
    }
    return true;
}

void sql_stmt(const char* stmt) {
    char *errmsg;
    int   ret;

    ret = sqlite3_exec(db, stmt, 0, 0, &errmsg);

    if (ret != SQLITE_OK) {
        printf("Error in statement: %s [%s].\n", stmt, errmsg);
    }
}

bool prepare_statement(const char* query) {
    int return_code = sqlite3_prepare(db, 
    query,  // stmt
    -1, // If less than zero, then stmt is read up to the first null terminator
    &stmt,
    NULL); // Pointer to unused portion of stmt
    
    if (return_code != SQLITE_OK) {
        printf("\nCould not prepare statement. Return code: %d\n", return_code);
        return false;
    }
    return true;
}

bool bind_text(int index, string text) {
    int ret_code = sqlite3_bind_text(stmt, index, text.c_str(), text.length(), SQLITE_STATIC);
    if (ret_code != SQLITE_OK) {
        return false;
    }
    return true;
}

bool bind_text(int index, char* text, int len) {
    int ret_code = sqlite3_bind_text(stmt, index, text, len, SQLITE_STATIC);
    if (ret_code != SQLITE_OK) {
        return false;
    }
    return true;
}

void encrypt(string pass, char* buf, unsigned int ops) {
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str(buf, 
        pass.c_str(), 
        pass.length(), 
        ops, 
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
        
    if (ret_value != 0) {
        buf = NULL;
    }
    return;
}

bool verify(string pass, char* hash) {
    if (hash == NULL) {
        return false;
    }
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str_verify(hash, pass.c_str(), pass.length());
    if (ret_value != 0) {
        return false;
    }
    return true;
}

bool check_existing(string user) {
    bool prepared = prepare_statement("select * from user where name = ?");
    
    if (prepared) {
        bind_text(1, user);
        sqlite3_step(stmt);
        if (sqlite3_column_text(stmt, 0) != NULL) { //if not null, this name has an entry (it's taken)
                return false;
        }
    }
    return true;
}

void print_bytes(const void *object, size_t size) {
    // This is for C++; in C just drop the static_cast<>() and assign.
    const unsigned char * const bytes = static_cast<const unsigned char *>(object);
    size_t i;

    for (i = 0; i < size; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

void register_user() {
    printf("Enter a username: ");
    string name;
    cin >> name;
    
    bool valid_length = name.length() > 0 && name.length() < 20;
    bool name_available = check_existing(name);
    while (!valid_length || !name_available) {
        if (!valid_length) {
            printf("Name must be at least 1 character and less than 20 characters.\n");
        } else if (!name_available) {
            printf("The username %s is taken.\n", name.c_str());
        }
        printf("Enter a username: ");
        cin >> name;
        valid_length = name.length() > 0 && name.length() < 20;
        name_available = check_existing(name);
    }
    
    printf("Select a password: ");
    string password;
    cin >> password;
    
    while (password.length() == 0 || password.length() > 30) {
        printf("Password must be at least 1 character and less than 30 characters.\n");
        cin >> password;
    }
    
    //Encrypt passwrd
    char hash_buffer[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    encrypt(password, hash_buffer, AMT_OPERATIONS);
    bool prepared = prepare_statement("insert into user ( NAME , PASSWORD, SALT ) values (?, ?, 'salt')");
        
    if (prepared) {
        bool bind1 = bind_text(1, name);
        bool bind2 = bind_text(2, hash_buffer, strlen(hash_buffer));
            
        //Executed paramaterized query
        int eval_code = sqlite3_step(stmt);
        if (eval_code != SQLITE_DONE) {
            printf("Could not step (execute). Error Code: %d. Error message: %s\n", eval_code, sqlite3_errmsg(db));
            if (eval_code == SQLITE_ERROR) {
                printf("Something went wrong.\n");
            } 
        } else {
                printf("Registered user: %s\n", name.c_str());
        }
    }
    return;
}

void login() {
    printf("Enter your username: ");
    string name;
    cin >> name;
    printf("Enter your password: ");
    string password;
    cin >> password;
    
    if (sqlite3_open(db_name, &db) == SQLITE_OK) {
        logged_in = true;
        current_user = "jeff";
        
        
    } else {
        printf("Failed to open db.\n");
        return;
    }
}

void check_messages() {
    cout << "Hello! You have one new message from Boba! Would you like to read the message? (Y/N) ";
    string read;
    cin >> read;
    if (read[0] == 'Y' || read[0] == 'y') {
        //read();
    } else if (read[0] == 'N' || read[0] == 'n') {
        cout << "You have no new messages!";

    }
    
    cout << "Would you like to write a message? (Y/N) ";
    string write;
    cin >> write;
    if (write[0] == 'Y' || write[0] == 'y') {
        //write();
    } else {
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
        printf("\tr \t register a username\n\tl \t login\n\tq \t quit\n");
    } else {
        printf("\tc \t check messages\n\to \t open a message\n\tw \t write a message\n\tl \t logout\n\tq \t quit\n");
    }
}