#include <iostream>
#include <string.h>
#include <sqlite3.h>
#include <stdio.h>
#include <sodium.h>

#define AMT_OPERATIONS 2<<22

#define MAX_NAME_LENGTH 20
#define MIN_NAME_LENGTH 1

#define MAX_PASSPHRASE_LENGTH 20
#define MIN_PASSPHRASE_LENGTH 1

#define MAX_PASSWORD_LENGTH 30

#define MAX_MESSAGE_LEN 500
#define MIN_MESSAGE_LEN 10

#define LOGIN_ATTEMPTS 3

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
bool bind_int(int index, int value);
bool bind_text(int index, string text);
bool bind_text(int index, char* text, int len);
void encrypt(const char* pass, char*, unsigned int);
bool verify(const char* pass, char* hash);
bool check_existing(string user);
void print_bytes(const void *object, size_t size);
unsigned int get_amt_operations();
string raw2string(unsigned char* input, unsigned int input_size);
void string2raw(string in, unsigned char* out);
bool passphrase_valid(string);
void generate_hash(unsigned char* , const char* , string , unsigned int );

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
    
    printf("Welcome to Gee-Mail. Enter h for a list of commands.\n");
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
                printf("Enter r to register a new username or l to login.\n");
            } else if (input[0] == 'L' || input[0] == 'l') {
                login();
                if (logged_in) {
                    printf("Welcome, %s.\nEnter h for a list of commands.\n", current_user.c_str());
                } else {
                    printf("Enter r to register a new username or l to login.\n");
                }
            } else {
                printf("Command not recognized.\nEnter h for a list of commands.\n");
            }
        } else {
            if (input[0] == 'C' || input[0] == 'c') {
                check_messages();
                
            } else if (input[0] == 'R' || input[0] == 'r') {
                read_message();
                
            } else if (input[0] == 'W' || input[0] == 'w') {
                write_message();
                
            } else if (input[0] == 'L' || input[0] == 'l') {
                printf("Logging out %s.\n", current_user.c_str());
                current_user = "";
                logged_in = false;
            } else {
                printf("Command not recognized.\n");
            }
            printf("Enter h for a list of commands.\n");
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

bool bind_int(int index, int value){
    int ret_code = sqlite3_bind_int(stmt, index, value);
    if (ret_code != SQLITE_OK) {
        return false;
    }
    return true;
}

void encrypt(const char* pass, char* buf, unsigned int ops) {
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str(buf, 
        pass, 
        strlen(pass), 
        ops, 
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
        
    if (ret_value != 0) {
        buf = NULL;
    }
    return;
}

bool verify(const char* pass, char* hash) {
    if (hash == NULL) {
        return false;
    }
    int ret_value = crypto_pwhash_scryptsalsa208sha256_str_verify(hash, pass, strlen(pass));
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
        if (sqlite3_column_text(stmt, 0) != NULL) { //if not null, this name has an entry (it exists)
                return true;
        }
    }
    return false;
}

unsigned int get_amt_operations(){
    bool sign = randombytes_uniform(2) == 0 ? true : false;
    unsigned int fac, divi, ran, sum = 0;
    fac = AMT_OPERATIONS;
    divi = fac/10;
    ran = randombytes_uniform(divi);
    if(true){
        sum = fac + ran;
    }
    else{
        sum = fac - ran;
    }
    printf("Factor: %d, Div: %d, Random: %d, Sum: %d\n", fac, divi, ran, sum);
    return sum;
}

string raw2string(unsigned char* input, unsigned int input_size){
  int i;
  //the output needs to have room for 2*input_size chars
  char byte[2];
  string output;
  for(i = 0; i<input_size; i++){
    sprintf(byte, "%02X", input[i]);
    output.append(byte);
  }
  return output;
};

void string2raw(string in, unsigned char* out){
  //the output needs to have room for input_size/2 chars
  unsigned int i, t, hn, ln;
  for (t = 0,i = 0; i < in.length(); i+=2,++t) {
          hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
          ln = in[i+1] > '9' ? in[i+1] - 'A' + 10 : in[i+1] - '0';
          out[t] = (hn << 4 ) | ln;
  }
};

bool passphrase_valid(string phrase){
    return phrase.length() > 1 && phrase.length() < crypto_secretbox_KEYBYTES;
}

void generate_hash(unsigned char* hash, const char* salt, string passphrase, unsigned int iterations){
    cout << "Started generate hash" << endl;
    size_t hash_size = crypto_secretbox_KEYBYTES;
    string input_message_string = salt;
    input_message_string.append("0");
    const unsigned char* input_message = reinterpret_cast<const unsigned char*>(input_message_string.c_str());
    const unsigned char* key = reinterpret_cast<const unsigned char*>(passphrase.c_str());
    
    crypto_generichash(hash, hash_size,
                       input_message, input_message_string.length(),
                       key, passphrase.length());
    for(int i = 0; i < iterations; i++){
        input_message_string = salt;
        string hash_string = raw2string(hash, hash_size);
        input_message_string.append(hash_string);
        input_message_string.append("0");
        const unsigned char* input_message = reinterpret_cast<const unsigned char*>(input_message_string.c_str());
        crypto_generichash(hash, hash_size,
                       input_message, input_message_string.length(),
                       key, passphrase.length());
    }
    cout << "Ended generate hash" << endl;
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
    
    bool valid_length = name.length() > 0 && name.length() < MAX_NAME_LENGTH;
    bool name_taken = check_existing(name);
    while (!valid_length || name_taken) {
        if (!valid_length) {
            printf("Name must be at least 1 character and less than 20 characters.\n");
        } else if (name_taken) {
            printf("The username %s is taken.\n", name.c_str());
        }
        printf("Enter a username: ");
        cin >> name;
        valid_length = name.length() > 0 && name.length() < MAX_NAME_LENGTH;
        name_taken = check_existing(name);
    }
    
    printf("Select a password: ");
    //Must ignore the newline character left by cin >> user
    cin.ignore();
    char password[32];
    cin.getline(password, 32);

    cout << "You entered: " << password  << endl;
    
    while (strlen(password) == 0 || strlen(password) >= MAX_PASSWORD_LENGTH) {
        printf("Password must be at least 1 character and less than 30 characters.\n");
        cin.getline(password, 32);
    }
    
    //Lock the sensitive memory region
    sodium_mlock(password, sizeof password);
    
    //The amount of operations
    unsigned int amt_operations = get_amt_operations();
    //Encrypt passwrd
    char hash_buffer[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    encrypt(password, hash_buffer, amt_operations);
    
    //Unlock the sensitive memory region after encrypting
    sodium_munlock(password, sizeof password);
    
    bool prepared = prepare_statement("insert into user ( NAME , PASSWORD, ITER ) values (?, ?, ?)");
    
    if (prepared) {
        bool bind1 = bind_text(1, name);
        bool bind2 = bind_text(2, hash_buffer, strlen(hash_buffer));
        bool bind3 = bind_int(3, amt_operations);
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
    
    bool valid_length = name.length() > 0 && name.length() < MAX_NAME_LENGTH;
    while (!valid_length) {
        printf("Name must be at least 1 character and less than 20 characters.\n");
        cin >> name;
        valid_length = name.length() > 0 && name.length() < MAX_NAME_LENGTH;
    }
    
    if (!check_existing(name)) {
        printf("The username %s does not exist.\n", name.c_str());
        return;
    }
    
    cin.ignore();
    printf("Enter your password: ");
    char password[MAX_PASSWORD_LENGTH];
    cin.getline(password, sizeof password);
    
    while (strlen(password) == 0 || strlen(password) >= MAX_PASSWORD_LENGTH) {
        printf("Entered password doesn't meet length requirements.\nPassword must be at least 1 character and less than 30 characters.\n");
        cin.getline(password, sizeof password);
    }
    
    int tries = 0;
    
    
    /*Select user entry from database*/
    char hash_buffer[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    prepare_statement("select * from user where name = ?");
    bind_text(1, name);
    sqlite3_step(stmt);
    
    sodium_mlock(password, sizeof password);
    bool correct_pass = verify(password, (char*)sqlite3_column_text(stmt, 2));
    
    while (!correct_pass) {
        tries++;
        if (tries == LOGIN_ATTEMPTS) {
            printf("Number of tries exceeded.\nLogin failed.\n");
            return;
        } else {
            printf("Incorrect password.\nEnter your password: ");
            cin.getline(password, sizeof password);
            
            correct_pass = verify(password, (char*)sqlite3_column_text(stmt, 2));
            
        }
    }
    sodium_munlock(password, sizeof password);
    current_user = name;
    logged_in = true;
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
    printf("Enter your recipient username: ");
    string recipient;
    cin >> recipient;
    
    bool valid_username_length = recipient.length() >= MIN_NAME_LENGTH && recipient.length() < MAX_NAME_LENGTH;
    while (!valid_username_length) {
        printf("Name must be at least %d character and less than %d characters.\n", MIN_NAME_LENGTH, MAX_NAME_LENGTH);
        cin >> recipient;
        valid_username_length = recipient.length() >= MIN_NAME_LENGTH && recipient.length() < MAX_NAME_LENGTH;
    }
    
    if (!check_existing(recipient)) {
        printf("The username %s does not exist.\n", recipient.c_str());
        return;
    }
    
    cin.ignore();
    
    printf("Type your message: ");
    string message;
    getline(cin, message);
    
    bool valid_message_length = message.length() >= MIN_MESSAGE_LEN && message.length() < MAX_MESSAGE_LEN;
    while (!valid_message_length) {
        printf("Message must be at least %d character and less than %d characters.\n", MIN_MESSAGE_LEN, MAX_MESSAGE_LEN);
        getline(cin, message);
        valid_message_length = message.length() >= MIN_MESSAGE_LEN && message.length() < MAX_MESSAGE_LEN;
    }
    
    
    cin.ignore();
    
    printf("Type your passphrase: ");
    string passphrase;
    cin >> passphrase;
    
    bool valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
    while (!valid_message_length) {
        printf("Message must be at least %d character and less than %d characters.\n", MIN_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH);
        cin >> passphrase;
        valid_message_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
    }
    
    //start for writing messages
    
}

void help_info() {
    if (!logged_in) {
        printf("\th \t print help information\n\tr \t register a username\n\tl \t login\n\tq \t quit\n");
    } else {
        printf("\th \t print help information\n\tc \t check messages\n\tr \t read a message\n\tw \t write a message\n\tl \t logout\n\tq \t quit\n");
    }
}