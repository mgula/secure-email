#include <iostream>
#include <string.h>
#include <gcrypt.h>
#include <sqlite3.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <sodium.h>

using namespace std;

string current_user;

bool logged_in = false;

sqlite3* db;
const char* db_name = "secure.db";
sqlite3_stmt *stmt;
char hashed_password[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
int rc;


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

void sql_stmt(const char* stmt) {
  char *errmsg;
  int   ret;

  ret = sqlite3_exec(db, stmt, 0, 0, &errmsg);

  if(ret != SQLITE_OK) {
    printf("Error in statement: %s [%s].\n", stmt, errmsg);
  }
}

bool open_db_connection(){
    sqlite3_open(db_name, &db);

    if(db == 0) {
        printf("\nCould not open database.\n");
        return false;
    }
    return true;
}

bool close_db_connection(){
    sqlite3_close(db);

    if(db == 0) {
        printf("\nCould not close database.\n");
        return false;
    }
    return true;
}

bool prepare_statement(const char* query){
    int return_code;
    return_code = sqlite3_prepare(
    db, 
    query,  // stmt
    -1, // If than zero, then stmt is read up to the first nul terminator
    &stmt,
    NULL  // Pointer to unused portion of stmt
    );
    if ( return_code != SQLITE_OK) {
        printf("\nCould not prepare statement. Return code: %d\n", return_code);
        return false;
    }
    return true;
}

bool bind_text(int index, string text){
    int ret_code = sqlite3_bind_text(stmt,index,text.c_str(),text.length(),SQLITE_STATIC);
    if(ret_code != SQLITE_OK){
        return false;
    }
    return true;
}

bool validate_credentials(string un, string pw){
    //0 < len(username) < 20 
    //0 < len(password) < 30
    return un.length() > 0 && pw.length() > 0 && un.length() < 20 && pw.length() < 30;
}

void register_user() {
    cout << "Enter a username: ";
    string name;
    cin >> name;
    cout << "Select a password: ";
    string password;
    cin >> password;

    bool is_open = open_db_connection();
    bool valid_creds = validate_credentials(name, password);
    
    if(is_open && valid_creds){
        //Encrypt name & salt
        bool prepared = prepare_statement("insert into user ( NAME , PASSWORD, SALT ) values (?, ?, 'salt')");
        if( prepared ){
            cout << "Prepared" << endl;
            bool bind1 = bind_text(1, name);
            bool bind2 = bind_text(2, password);
            
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                printf("\nCould not step (execute) stmt.\n");
                return;
            }
            else{
                printf("Registered user: %s\n", name.c_str());
            }
        }
        cout << "Finished registration" << endl;
        close_db_connection();
    }
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

void raw2hex(char* input, char* output, int input_size){
  int i;
  //the output needs to have room for 2*input_size chars
  for(i = 0; i<input_size; i++){
    sprintf(output+i*2, "%02X", input[i]);
  }
};

void print_bytes(const void *object, size_t size)
{
  // This is for C++; in C just drop the static_cast<>() and assign.
  const unsigned char * const bytes = static_cast<const unsigned char *>(object);
  size_t i;

  for(i = 0; i < size; i++)
  {
    printf("%02X", bytes[i]);
  }
  printf("\n");
}

bool encrypt(string pass){
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str(hashed_password, pass.c_str(), pass.length(),crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN,crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
    if(ret_value != 0){
        return false;
    }
    return true;
}

bool verify(string pass, string hash){
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str_verify(hash.c_str(), pass.c_str(), pass.length());
    if(ret_value != 0){
        return false;
    }
    return true;
}

int main() {
    cout << "Welcome to Gee-Mail. Enter H for a list of commands. " << endl;
    string input;
    
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        printf("Panic\n");
        return 1;
    }
    string my_pass = "hey now";
    bool encrypted = encrypt(my_pass);
    bool conf = verify(my_pass, encrypted);
    printf("PASS: %s\nHASH: %s\nVERIFIED: %s\n", my_pass.c_str(), hashed_password, conf ? "true" : "false");
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
                register_user();
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
