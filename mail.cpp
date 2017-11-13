#include <iostream>
#include <string.h>
#include <sqlite3.h>
#include <stdio.h>
#include <sodium.h>
#include <limits> 

#define AMT_OPERATIONS 2<<22

#define MAX_NAME_LENGTH 20
#define MIN_NAME_LENGTH 1

#define MAX_PASSPHRASE_LENGTH 20
#define MIN_PASSPHRASE_LENGTH 1

#define MAX_PASSWORD_LENGTH 30

#define MAX_MESSAGE_LEN 500
#define MIN_MESSAGE_LEN 10

#define LOGIN_ATTEMPTS 3

#define CIPHERTEXT_PAD crypto_secretbox_MACBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define KEY_LEN crypto_secretbox_KEYBYTES

#define SALT "salty chips"
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
void generate_key(unsigned char* , const char* , string , unsigned int );
bool add_message(string recipient, string cipher, string nonce);

/*Methods that appear in main*/
void register_user();
void login();
void display_messages();
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
                display_messages();
                
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

bool add_message(string recipient, string cipher, string nonce){
    bool prepped = prepare_statement("INSERT INTO messages (SENDER, RECIPIENT, READ, MESSAGE, NONCE) VALUES (?, ?, ?, ?, ?)");
    bool ret_value = false;
    if(prepped){
        bool bound_sender = bind_text(1, current_user);
        bool bound_recipient = bind_text(2, recipient);
        bool bound_read = bind_int(3, 0); //1 = True, 0 = false
        bool bound_message = bind_text(4, cipher);
        bool bound_nonce = bind_text(5, nonce);
        
        if(bound_sender && bound_recipient && bound_read && bound_message && bound_nonce){
            int eval_code = sqlite3_step(stmt);
            if (eval_code != SQLITE_DONE) {
                printf("Could not step (execute). Error Code: %d. Error message: %s\n", eval_code, sqlite3_errmsg(db));
                if (eval_code == SQLITE_ERROR) {
                    printf("Something went wrong.\n");
                }
            } else {
                    ret_value = true;
                    printf("Message written\n");
            }
        }
    }
    return ret_value;
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
    bool prepared = prepare_statement("select * from users where name = ?");
    
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


void generate_key(unsigned char* hash, const char* salt, string passphrase, unsigned int iterations){
    size_t hash_size = KEY_LEN;
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
    
    bool prepared = prepare_statement("insert into users ( NAME , PASSWORD, ITER ) values (?, ?, ?)");
    
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
    prepare_statement("select * from users where name = ?");
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

void display_messages() {
    bool prepared = prepare_statement("select * from messages where recipient = ?");
    
    if (prepared) {
        bind_text(1, current_user);
        
        int rc = sqlite3_step(stmt);
        
        if (sqlite3_column_text(stmt, 0) == NULL) {
            printf("No messages at this time.\n");
            return;
        }
        
        printf("\tMessage ID\tSender\t\tRead\n");
        
        while (rc == SQLITE_ROW) {
            char* id = (char*)sqlite3_column_text(stmt, 0);
            char* sender = (char*)sqlite3_column_text(stmt, 1);
            int read = sqlite3_column_int(stmt, 3);
            
            string read_string = "";
            if (read == 0) {
                read_string = "No";
            } else if (read == 1) {
                read_string = "Yes";
            } else {
                read_string = "No clue man";
            }
            
            printf("\t %s\t\t %s\t\t %s\n", id, sender, read_string.c_str());
            
            rc = sqlite3_step(stmt);
        }
    }
}

void read_message() {
    int id;
    
    while(true){
        printf("Enter the message id: ");
        if (cin >> id) {
            if(id < 0){
                printf("Enter a non-negative message id\n");
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }else{
                break;
            }
        } else {
            printf("Enter an integer\n");
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }
    
    //Get that message
    bool prepared = prepare_statement("select MESSAGE, NONCE from messages where recipient = ? AND id = ?");
    
    if(prepared){
        
        bind_text(1, current_user);
        bind_int(2, id);
        
        sqlite3_step(stmt);
        
        if (sqlite3_column_text(stmt, 0) == NULL) {
            printf("Could not retrieve message with that ID.\n");
            return;
        }
        
        printf("Type your passphrase: ");
        string passphrase;
        cin >> passphrase;
                
        bool valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
        while (!valid_passphrase_length) {
            printf("Message must be at least %d character and less than %d characters.\n", MIN_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH);
            cin >> passphrase;
            valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
        }
        
        
        string cipher_text = (char*)sqlite3_column_text(stmt, 0);
        string nonce_text = (char*)sqlite3_column_text(stmt, 1);
        
        int cipher_len = cipher_text.length()/2;
        int message_len = (cipher_len - CIPHERTEXT_PAD);
        
        unsigned char cipher[cipher_len];
        unsigned char nonce[NONCE_LEN];
        
        unsigned char decrypt[message_len];
        
        //Key buffer used for autherntication
        unsigned char key[KEY_LEN];
        
        //This dumps the bytes into the key buffer
        generate_key(key, SALT, passphrase, 3);
        
        string2raw(cipher_text, cipher);
        string2raw(nonce_text, nonce);
        
        int ret_code = crypto_secretbox_open_easy(decrypt, cipher, sizeof cipher, nonce, key);
        if(ret_code != 0){
            printf("Failed\n");
        }
        else{
            printf("Decrypt Success\n");
            string casted = (const char*)decrypt;
            casted = casted.substr(0,message_len);
            printf("Message: %s\n", casted.c_str());
            
            //Set the read flag to true
            prepare_statement("UPDATE messages SET read=1 WHERE id=?");
            bind_int(1,id);
            int rc = sqlite3_step(stmt);
            if(rc == SQLITE_DONE){
                printf("Updated the flag\n");
            }
            else{
                printf("Failed update\n");
            }
        }
    }
    //code to read the message
    return;
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
    
    
    printf("Type your passphrase: ");
    string passphrase;
    cin >> passphrase;
    
    bool valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
    while (!valid_passphrase_length) {
        printf("Message must be at least %d character and less than %d characters.\n", MIN_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH);
        cin >> passphrase;
        valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
    }
    
    //Key buffer used for autherntication
    unsigned char key[KEY_LEN];
    
    //This dumps the bytes into the key buffer
    generate_key(key, SALT, passphrase, 3);
    
    //Compute the ciphertext length from the length of the message
    int message_length = message.length();
    int cipher_length = CIPHERTEXT_PAD + message_length;
    
    //The cipher buffers and nonce buffers
    unsigned char cipher[cipher_length];
    unsigned char nonce[NONCE_LEN];
    
    //The message string casted to a const unsigned char*
    const unsigned char* mess = (const unsigned char*)message.c_str();
    
    //Get a random nonce
    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(cipher, mess, message_length, nonce, key);
    
    //Save this cipher in db
    string cipher_text = raw2string(cipher, cipher_length);
    string nonce_text = raw2string(nonce, NONCE_LEN);
    
    // printf("Cipher text: %s\n", cipher_text.c_str());
    // printf("Nonce text: %s\n", nonce_text.c_str());
    
    bool success = add_message(recipient,cipher_text,nonce_text);
    //start for writing messages
    
}

void help_info() {
    if (!logged_in) {
        printf("\th \t print help information\n\tr \t register a username\n\tl \t login\n\tq \t quit\n");
    } else {
        printf("\th \t print help information\n\tc \t check messages\n\tr \t read a message\n\tw \t write a message\n\tl \t logout\n\tq \t quit\n");
    }
}