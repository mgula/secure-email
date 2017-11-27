#include <iostream>
#include <string.h>
#include <sqlite3.h>
#include <stdio.h>
#include <sodium.h>
#include <limits> 

#define AMT_OPERATIONS 2 << 22

#define MAX_NAME_LENGTH 20
#define MIN_NAME_LENGTH 1

#define MAX_PASSPHRASE_LENGTH 20
#define MIN_PASSPHRASE_LENGTH 1

#define MAX_PASSWORD_LENGTH 30

#define MAX_MESSAGE_LEN 500
#define MIN_MESSAGE_LEN 1

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
unsigned int get_amt_operations();
string raw_to_string(unsigned char* input, unsigned int input_size);
void string_to_raw(string in, unsigned char* out);
void generate_key(unsigned char* , const char* , string , unsigned int );
bool add_message(string recipient, string cipher, string nonce);

/*Methods that appear in main*/
void register_user();
void login();
void display_messages();
void read_message();
void write_message();
void help_info();

/*Add admins
add sent folder*/
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
    sqlite3_finalize(stmt);
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
    char* errmsg;
    int ret = sqlite3_exec(db, stmt, 0, 0, &errmsg);
    if (ret != SQLITE_OK) {
        printf("Error in statement: %s [%s].\n", stmt, errmsg);
    }
}

bool prepare_statement(const char* query) {
    rc = sqlite3_prepare(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Could not prepare statement. Return code: %d\n", rc);
        return false;
    }
    return true;
}

bool bind_int(int index, int value){
    rc = sqlite3_bind_int(stmt, index, value);
    if (rc != SQLITE_OK) {
        printf("Error binding statement parameters.\n");
        return false;
    }
    return true;
}

bool bind_text(int index, string text) {
    rc = sqlite3_bind_text(stmt, index, text.c_str(), text.length(), SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        printf("Error binding statement parameters.\n");
        return false;
    }
    return true;
}

bool bind_text(int index, char* text, int len) {
    rc = sqlite3_bind_text(stmt, index, text, len, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        printf("Error binding statement parameters.\n");
        return false;
    }
    return true;
}

void encrypt(const char* pass, char* buf, unsigned int ops) {
    rc = crypto_pwhash_scryptsalsa208sha256_str(buf, 
        pass, 
        strlen(pass), 
        ops, 
        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN);
        
    if (rc != 0) {
        buf = NULL;
    }
}

bool verify(const char* pass, char* hash) {
    if (hash == NULL) {
        return false;
    }
    
    rc = crypto_pwhash_scryptsalsa208sha256_str_verify(hash, pass, strlen(pass));
    
    if (rc != 0) {
        return false;
    }
    return true;
}

bool check_existing(string user) {
    bool prepared = prepare_statement("SELECT ID FROM USERS WHERE NAME = ?;");
    
    if (prepared) {
        bool bound_user = bind_text(1, user);
        if (bound_user) {
            sqlite3_step(stmt);
            if (sqlite3_column_text(stmt, 0) != NULL) { //if not null, this name has an entry (it exists)
                    return true;
            }
        }
    }
    return false;
}

unsigned int get_amt_operations(){
    bool sign = randombytes_uniform(2) == 0 ? true : false;
    
    unsigned int fac, divi, ran, sum = 0;
    
    fac = AMT_OPERATIONS;
    divi = fac / 10;
    ran = randombytes_uniform(divi);
    
    if (sign) {
        sum = fac + ran;
    } else {
        sum = fac - ran;
    }
    
    return sum;
}

string raw_to_string(unsigned char* input, unsigned int input_size) {
    //the output needs to have room for 2*input_size chars
    char byte[2];
    string output;
    
    for (int i = 0; i < input_size; i++) {
        sprintf(byte, "%02X", input[i]);
        output.append(byte);
    }
    
    return output;
}

void string_to_raw(string in, unsigned char* out) {
    //the output needs to have room for input_size/2 chars
    unsigned int i, t, hn, ln;
    for (t = 0,i = 0; i < in.length(); i += 2, ++t) {
        hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
        ln = in[i + 1] > '9' ? in[i + 1] - 'A' + 10 : in[i + 1] - '0';
        out[t] = (hn << 4 ) | ln;
    }
}


void generate_key(unsigned char* hash, const char* salt, string passphrase, unsigned int iterations){
    size_t hash_size = KEY_LEN;
    string input_message_string = salt;
    
    input_message_string.append("0");
    
    const unsigned char* input_message = reinterpret_cast<const unsigned char*>(input_message_string.c_str());
    const unsigned char* key = reinterpret_cast<const unsigned char*>(passphrase.c_str());
    
    crypto_generichash(hash, 
        hash_size,
        input_message,
        input_message_string.length(),
        key, 
        passphrase.length());
                       
    for (int i = 0; i < iterations; i++) {
        input_message_string = salt;
        string hash_string = raw_to_string(hash, hash_size);
        input_message_string.append(hash_string);
        input_message_string.append("0");
        const unsigned char* input_message = reinterpret_cast<const unsigned char*>(input_message_string.c_str());
        crypto_generichash(hash, 
            hash_size,
            input_message, 
            input_message_string.length(),
            key, 
            passphrase.length());
    }
}

bool add_message(string recipient, string cipher, string nonce) {
    bool prepared = prepare_statement("INSERT INTO MESSAGES (SENDER, RECIPIENT, READ, MESSAGE, NONCE) VALUES (?, ?, ?, ?, ?);");
    
    if (prepared) {
        bool bound_sender = bind_text(1, current_user);
        bool bound_recipient = bind_text(2, recipient);
        bool bound_read = bind_int(3, 0); //1 = True, 0 = false
        bool bound_message = bind_text(4, cipher);
        bool bound_nonce = bind_text(5, nonce);
        
        if (bound_sender && bound_recipient && bound_read && bound_message && bound_nonce) {
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                printf("Could not step (execute). Error Code: %d. Error message: %s\n", rc, sqlite3_errmsg(db));
                if (rc == SQLITE_ERROR) {
                    printf("Something went wrong.\n");
                }
            } else {
                printf("Message sent.\n");
                return true;
            }
        }
    }
    return false;
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
    cin.ignore(); // ignore the newline character left by cin >> user
    char password[32];
    cin.getline(password, 32);
    
    while (strlen(password) == 0 || strlen(password) >= MAX_PASSWORD_LENGTH) {
        printf("Password must be at least 1 character and less than 30 characters.\n");
        cin.getline(password, 32);
    }
    
    sodium_mlock(password, sizeof password); // Lock the sensitive memory region
    
    unsigned int amt_operations = get_amt_operations();
    char hash_buffer[crypto_pwhash_scryptsalsa208sha256_STRBYTES];
    
    encrypt(password, hash_buffer, amt_operations);
    
    sodium_munlock(password, sizeof password); // Unlock the sensitive memory region after encrypting
    
    bool prepared = prepare_statement("INSERT INTO USERS ( NAME , PASSWORD, ITER ) VALUES (?, ?, ?);");
    
    if (prepared) {
        bool bound_name = bind_text(1, name);
        bool bound_hash = bind_text(2, hash_buffer, strlen(hash_buffer));
        bool bound_ops = bind_int(3, amt_operations);
        
        if (bound_name && bound_hash && bound_ops) {
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                printf("Could not step (execute). Error Code: %d. Error message: %s\n", rc, sqlite3_errmsg(db));
                if (rc == SQLITE_ERROR) {
                    printf("Something went wrong.\n");
                } 
            } else {
                printf("Registered user %s.\n", name.c_str());
            }
        }
    }
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
    
    /*Select user entry from database*/
    bool prepared = prepare_statement("SELECT PASSWORD FROM USERS WHERE NAME = ?;");
    
    if (prepared) {
        bool bound_name = bind_text(1, name);
        if (bound_name) {
            sqlite3_step(stmt);
        }
    }
    
    sodium_mlock(password, sizeof password);
    
    char* db_hash = (char*)sqlite3_column_text(stmt, 0);
    
    if (db_hash == NULL) {
        printf("Error accessing database.\n");
        sodium_munlock(password, sizeof password);
        return;
    }
    
    bool correct_pass = verify(password, db_hash);
    
    int tries = 0;
    
    while (!correct_pass) {
        tries++;
        if (tries == LOGIN_ATTEMPTS) {
            printf("Number of tries exceeded.\nLogin failed.\n");
            return;
        } else {
            printf("Incorrect password.\nEnter your password: ");
            cin.getline(password, sizeof password);
            correct_pass = verify(password, db_hash);
        }
    }
    
    sodium_munlock(password, sizeof password);
    
    current_user = name;
    logged_in = true;
}

void display_messages() {
    printf("Displaying all messages to user %s:\n", current_user.c_str());
    bool prepared = prepare_statement("SELECT ID, SENDER, READ FROM MESSAGES WHERE RECIPIENT = ?;");
    
    if (prepared) {
        bool bound_user = bind_text(1, current_user);
        
        if (bound_user) {
            rc = sqlite3_step(stmt);
            
            if (sqlite3_column_text(stmt, 0) == NULL) {
                printf("No messages at this time.\n");
                return;
            }
        
            printf("\tMessage ID\t\t\tSender\t\t\t\tRead\n");
        
            while (rc == SQLITE_ROW) {
                char* id = (char*)sqlite3_column_text(stmt, 0);
                char* sender = (char*)sqlite3_column_text(stmt, 1);
                int read = sqlite3_column_int(stmt, 2);
            
                string read_string = "";
                if (read == 0) {
                    read_string = "No";
                } else if (read == 1) {
                    read_string = "Yes";
                } else {
                    read_string = "No clue man";
                }
            
                printf("\t%6s %28s %32s\n", id, sender, read_string.c_str());
            
                rc = sqlite3_step(stmt);
            }
        }
    }
}

void read_message() {
    bool prepared = prepare_statement("SELECT ID FROM MESSAGES WHERE RECIPIENT = ?;");
    
    if (prepared) {
        bool bound_user = bind_text(1, current_user);
        
        if (bound_user) {
            sqlite3_step(stmt); // Don't check return code here
        } else {
            return;
        }
    } else {
        return;
    }
    
    if (sqlite3_column_text(stmt, 0) == NULL) {
        printf("You have no messages to select from.\n");
        return;
    }
    
    int id;
    
    while (true) {
        printf("Enter the message ID: ");
        if (cin >> id) {
            if (id < 0) {
                printf("Message ID must be non-negative.\n");
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            } else {
                break;
            }
        } else {
            printf("Message ID must be an integer.\n");
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }
    
    prepared = prepare_statement("SELECT READ, MESSAGE, NONCE FROM MESSAGES WHERE RECIPIENT = ? AND ID = ?;");
    
    if (prepared) {
        
        bool bound_name = bind_text(1, current_user);
        bool bound_id = bind_int(2, id);
        
        if (bound_name && bound_id) {
            sqlite3_step(stmt); // or here
        } else {
            return;
        }
            
        if (sqlite3_column_text(stmt, 0) == NULL) {
            printf("Could not retrieve message with ID %d.\n", id);
            return;
        }
        
        printf("Type your shared passphrase: ");
        string passphrase;
        cin >> passphrase;
                
        bool valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
        
        while (!valid_passphrase_length) {
            printf("Shared passphrase must be at least %d characters and less than %d characters.\n", MIN_PASSPHRASE_LENGTH, MAX_PASSPHRASE_LENGTH);
            cin >> passphrase;
            valid_passphrase_length = passphrase.length() >= MIN_PASSPHRASE_LENGTH && passphrase.length() < MAX_PASSPHRASE_LENGTH;
        }
        
        string cipher_text = (char*)sqlite3_column_text(stmt, 1);
        string nonce_text = (char*)sqlite3_column_text(stmt, 2);
        
        int cipher_len = cipher_text.length()/2;
        int message_len = (cipher_len - CIPHERTEXT_PAD);
        
        unsigned char cipher[cipher_len];
        unsigned char nonce[NONCE_LEN];
        
        unsigned char decrypt[message_len];
        
        unsigned char key[KEY_LEN]; // Key buffer used for authentication
        
        generate_key(key, SALT, passphrase, 3); // This dumps the bytes into the key buffer
        
        string_to_raw(cipher_text, cipher);
        string_to_raw(nonce_text, nonce);
        
        rc = crypto_secretbox_open_easy(decrypt, cipher, sizeof(cipher), nonce, key);
        
        if (rc != 0) {
            printf("Incorrect passphrase.\n");
        } else {
            string casted = (const char*)decrypt;
            casted = casted.substr(0, message_len);
            printf("Message: %s\n", casted.c_str());
            
            int read = sqlite3_column_int(stmt, 0);
            
            if (read == 0) {
                prepared = prepare_statement("UPDATE MESSAGES SET READ = 1 WHERE ID = ?;"); // Set the read flag to true
                if (prepared) {
                    bound_id = bind_int(1, id);
                    if (bound_id) {
                        rc = sqlite3_step(stmt);
                        if (rc == SQLITE_DONE) {
                            printf("Message marked as read.\n");
                        } else {
                            printf("Could not mark message as read.\n");
                        }
                    }
                }
            }
        }
    }
}

void write_message() {
    printf("Enter the recipient's username: ");
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
    
    unsigned char key[KEY_LEN]; // Key buffer used for autherntication
    
    generate_key(key, SALT, passphrase, 3); // This dumps the bytes into the key buffer
    
    int message_length = message.length();
    int cipher_length = CIPHERTEXT_PAD + message_length; // Compute the ciphertext length
    
    unsigned char cipher[cipher_length];
    unsigned char nonce[NONCE_LEN];
    
    const unsigned char* mess = (const unsigned char*)message.c_str();
    
    randombytes_buf(nonce, sizeof nonce); // Get a random nonce
    
    crypto_secretbox_easy(cipher, mess, message_length, nonce, key);
    
    string cipher_text = raw_to_string(cipher, cipher_length);
    string nonce_text = raw_to_string(nonce, NONCE_LEN);
    
    add_message(recipient, cipher_text, nonce_text); // Save this cipher in db
}

void help_info() {
    if (!logged_in) {
        printf("\th \t print help information\n\tr \t register a username\n\tl \t login\n\tq \t quit\n");
    } else {
        printf("\th \t print help information\n\tc \t check messages\n\tr \t read a message\n\tw \t write a message\n\tl \t logout\n\tq \t quit\n");
    }
}