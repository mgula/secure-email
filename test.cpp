#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <assert.h>

using namespace std;

#define MAX_MESSAGE_LEN 500
#define MIN_MESSAGE_LEN 10

#define CIPHERTEXT_PAD crypto_secretbox_MACBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define KEY_LEN crypto_secretbox_KEYBYTES

void print_bytes(const void *object, size_t size);
string hash2string(unsigned char* input, unsigned int input_size);
void string2hash(string in, unsigned char* out);
bool passphrase_valid(string);
void generate_hash(unsigned char* , const char* , string , unsigned int );
void get_cipher(unsigned char* cipher, unsigned char* nonce,  unsigned char* key, string message);

void print_bytes(const void *object, size_t size) {
    // This is for C++; in C just drop the static_cast<>() and assign.
    const unsigned char * const bytes = static_cast<const unsigned char *>(object);
    size_t i;

    for (i = 0; i < size; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
};

string hash2string(unsigned char* input, unsigned int input_size){
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

void string2hash(string in, unsigned char* out){
  //the output needs to have room for input_size/2 chars
  unsigned int i, t, hn, ln;
  for (t = 0,i = 0; i < in.length(); i+=2,++t) {
          hn = in[i] > '9' ? in[i] - 'A' + 10 : in[i] - '0';
          ln = in[i+1] > '9' ? in[i+1] - 'A' + 10 : in[i+1] - '0';
          out[t] = (hn << 4 ) | ln;
  }
};

bool passphrase_valid(string phrase){
    return phrase.length() > 1 && phrase.length() < KEY_LEN;
}

bool message_valid(string message){
    return message.length() > MIN_MESSAGE_LEN && message.length() < MAX_MESSAGE_LEN;
}

void generate_hash(unsigned char* hash, const char* salt, string passphrase, unsigned int iterations){
    cout << "Started generate hash" << endl;
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
        string hash_string = hash2string(hash, hash_size);
        input_message_string.append(hash_string);
        input_message_string.append("0");
        const unsigned char* input_message = reinterpret_cast<const unsigned char*>(input_message_string.c_str());
        crypto_generichash(hash, hash_size,
                       input_message, input_message_string.length(),
                       key, passphrase.length());
    }
    cout << "Ended generate hash" << endl;
}

void get_cipher(unsigned char* cipher, unsigned char* nonce,  unsigned char* key, string message){
    
}

int main(){
    /*Check sodium status*/
    if (sodium_init() < 0) {
        printf("Sodium may not have been properly installed.\n");
        return 1;
    }
    //-----------------------------------------------------------
    //Start Key Generation
    //Get the passphrase [Assumed to be one word]
    string shared_passphrase;
    while(! passphrase_valid(shared_passphrase)){
        printf("Enter secret phrase: ");
        cin >> shared_passphrase;
    }
    
    //Print out the input
    cout << shared_passphrase << endl;
    
    //Declare the hash buffer
    unsigned char hash[KEY_LEN];
    
    //Generate the hash with some arbitray salt and iterations
    generate_hash(hash, "salty chips", shared_passphrase, 3);
    //Store the hash buffer as a string
    string hash2string(hash,KEY_LEN);
    //This will be the key used in the crypto_secret_box
    //Store this string in the db
    
    //--------------------------------------------------------
    //Start Message encryption
    string message;
    //Ignore the newline character leftover by the previous cin
    cin.ignore();
    while(! message_valid(message)){
        printf("Enter message: ");
        getline(cin, message);
    }
    
    //The length of the message
    int message_length = message.length();
    //The stored ciphertext is the length of the message + the length of the ciphertext padding
    int cipher_length = CIPHERTEXT_PAD + message_length;
    
    printf("Cipher text MAC: %d\n", CIPHERTEXT_PAD);
    
    //Encrypt variables
    unsigned char cipher[cipher_length];
    unsigned char nonce[NONCE_LEN];
    const unsigned char* mess = (const unsigned char*)message.c_str();
    
    
    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(cipher, mess, message_length, nonce, hash);
    
    int message_len = ((int)(sizeof cipher_decrypt) - CIPHERTEXT_PAD);
    unsigned char cipher_decrypt[cipher_length];
    unsigned char nonce_decrypt[NONCE_LEN];
    unsigned char decrypted[message_length];
    
    string cipher_hex = hash2string(cipher, sizeof cipher);
    string nonce_hex = hash2string(nonce, sizeof nonce);
    string2hash(cipher_hex, cipher_decrypt);
    string2hash(nonce_hex, nonce_decrypt);
    printf("String: %s\nCipher:%s\n", message.c_str(), cipher_hex.c_str());
    
    int ret_code = crypto_secretbox_open_easy(decrypted, cipher_decrypt, sizeof cipher, nonce_decrypt, hash);
    if(ret_code != 0){
        printf("Failed\n");
    }
    
    else{
        printf("Success\n");
        string casted = (const char*)decrypted;
        casted = casted.substr(0,message_len);
        cout <<  casted << endl;
        
    }
    
    return 0;
}