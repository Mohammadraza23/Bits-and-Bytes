#include <stdio.h>
#include <string.h>

#define MAX_BUF  256

#define IV  0b10110001
#define KEY 0b11001011
#define CTR 0b00110101

void encode(unsigned char*, unsigned char*, int);
void decode(unsigned char*, unsigned char*, int);

unsigned char processCtr(unsigned char, unsigned char);
unsigned char encryptByte(unsigned char, unsigned char, unsigned char);
unsigned char decryptByte(unsigned char, unsigned char, unsigned char);

unsigned char getBit(unsigned char, int);
unsigned char setBit(unsigned char, int);
unsigned char clearBit(unsigned char, int);

void display_string(unsigned char*, int, char*);

int main()
{
  unsigned char message[MAX_BUF];         // to store the message
  unsigned char ciper_text[MAX_BUF];      // the cipered text got from encryption
  int  choice;

  printf("\nYou may:\n");
  printf("  (1) Encrypt a message \n");
  printf("  (2) Decrypt a message \n");
  printf("  (0) Exit\n");
  printf("\n what is your selection: ");
  scanf("%d", &choice);
  getchar();      // to skip '\n' from the last input of choice as fgets read the char if there is the buffer of scanf so making the buffer clear to be ready for fgets

  if (choice == 0)
    return 0;

  int i=0, char_, size;
  switch (choice) {
    case 1:
      // getting input in the message array of character
      fgets((char*)message, sizeof(message), stdin);
      // geting the size of the message array
      size = strlen((char*)message);
      // giving the message, ciper array and number of bytes in the encode() as we have to read the last byte which is '\n' so giving size.
      encode(message, ciper_text, size);
      // adding null at the end of the ciper text
      ciper_text[size] = 0;
      // printing the ciper text
      display_string(ciper_text, size, "%d ");
      break;
    case 2:
      // getting input unless the last entry is -1
      do{
        // reading integers and adding it into the ciper text array
        scanf("%d", &char_);
        ciper_text[i++] = char_;  // i++ will first give the value of i and then increment the value of i later
      }while( char_ != -1);
      // placing null at the end of the ciper text array
      ciper_text[--i] = 0;
      // calling decode method and giveing ciper text, message array (the result) and size of the ciper text
      decode(ciper_text, message, i);
      // priting the message array with size and format
      display_string(message, i,"%c");
      break;
  }
  return(0);
}

//displaying output
void display_string(unsigned char* str, int size, char* format){
  for(int i=0; i<size; i++)
    printf(format, str[i]);
    printf("\n");
}

/*
  Function:  encode
  Purpose:   encrypts each plaintext character into coressponding ciphertext byte
       in:   pt- array of plaintext characters
       in:   ct- encrypted byte stored in ct array
       in:   numBytes- number of bytes
*/
void encode(unsigned char* pt, unsigned char* ct, int numBytes){
  unsigned char key = (unsigned char) KEY;
  unsigned char ctr = processCtr(key, (unsigned char) CTR);
  unsigned char iv = (unsigned char) IV;
  for(int i=0;i<numBytes;i++){
    // using the ctr initial value and then processing the ctr value with the key to get the new ctr
    // a xor b = c and b xor c = a // this is technique which is used to encrypt and decrypt
    ct[i] = encryptByte(pt[i], ctr, ( i==0 ? iv : ct[i-1] ) ); // if the value of i is 0 then return iv else return the previous ciper text value
    ctr = processCtr(key, ++ctr );
  }
}

/*
  Function:  decode
  Purpose:   decrypts each ciphertext byte character into coressponding plaintext byte
      in:   ct- encrypted byte stored in ct array
       in:   pt- array of plaintext characters
       in:   numBytes- number of bytes
*/
void decode(unsigned char* ct, unsigned char* pt, int numBytes){
  unsigned char key = (unsigned char) KEY;
  unsigned char ctr = processCtr(key, (unsigned char) CTR);
  unsigned char iv = (unsigned char) IV;
  for(int i=0;i<numBytes;i++){
    pt[i] = decryptByte(ct[i], ctr, ( i==0 ? iv : ct[i-1] ) );
    ctr = processCtr(key, ++ctr );
  }
}

/*
  Function:  processCtr
  Purpose:   processes the given counter value with the given key
       in:   ctr- counter value
       in:   key- given key value
   return:   returning the counter
*/
unsigned char processCtr(unsigned char key, unsigned char counter){
  // making a temporary counter
  unsigned char temp_counter = counter;
  int i = 1;    // assuming the the value of counter is odd so setting the value of i to 1
  if(!(counter & 1)){  // if the value of counter is even then set the value of i to 0
    i = 0;
  }
  // iterating through the bytes skipping one between
  for(;i<=7;i+=2){
    // if the xor value of the bit counter and key is 1 then set the bit of temporary counter else set 0
    temp_counter = getBit(counter, i) ^ getBit(key, i) ? setBit(temp_counter, i) : clearBit(temp_counter, i);
  }
  return temp_counter;
}

/*
  Function:  encryptByte
  Purpose:   encrypts user plaintext
       in:   pt- plaintext byte
       in:   ctr- counter value
       in:   prev- previous byte of the ciphertext
   return:   returns the corresponding encrypted ciphertext byte as the return value
*/
unsigned char encryptByte(unsigned char pt, unsigned char ctr, unsigned char prev) {
  unsigned char temp = 0;     // making a temporary variable with 0 bits
  for(int i=0;i<=7;i++){
    // if the current bit of ctr is 1 then xor the bits of pt and previous value bit and set the bit of temp to 1 if it returns 1 else 0
    if(getBit(ctr,i)) {
      temp = ( getBit(pt,i) ^ getBit(prev,i) ) ? setBit(temp,i) : clearBit(temp,i);
    }else {
      // 7-i will return the mirror bit of the byte
      temp = ( getBit(pt,i) ^ getBit(prev,7-i) ) ? setBit(temp,i) : clearBit(temp,i);
    }
  }
  return temp;
}

/*
  Function:  decryptByte
  Purpose:   decrypts user ciphertext
       in:   ct- ciphertext byte
       in:   ctr- counter value
       in:   prev- previous byte of the ciphertext
   return:   returns the corresponding decrypted plaintext byte as the return value
*/
unsigned char decryptByte(unsigned char ct, unsigned char ctr, unsigned char prev) {
  unsigned char temp = 0;
  for(int i=0;i<=7;i++){
    if(getBit(ctr,i)) {
      temp = ( getBit(ct,i) ^ getBit(prev,i) ) ? setBit(temp,i) : clearBit(temp,i);
    }else {
      temp = ( getBit(ct,i) ^ getBit(prev,7-i) ) ? setBit(temp,i) : clearBit(temp,i);
    }
  }
  return temp;
}

/*
  Function:  getBit
  Purpose:   retrieve value of bit at specified position
       in:   character from which a bit will be returned
       in:   position of bit to be returned
   return:   value of bit n in character c (0 or 1)
*/
unsigned char getBit(unsigned char c, int n)
{
  return ((c& (1<<n) )>>n);
}

/*
  Function:  setBit
  Purpose:   set specified bit to 1
       in:   character in which a bit will be set to 1
       in:   position of bit to be set to 1
   return:   new value of character c with bit n set to 1
*/
unsigned char setBit(unsigned char c, int n)
{
  c=(c| (1<<n) );
  return c;
}

/*  Function:  clearBit
  Purpose:   set specified bit to 0
       in:   character in which a bit will be set to 0
       in:   position of bit to be set to 0
   return:   new value of character c with bit n set to 0
*/
unsigned char clearBit(unsigned char c, int n)
{
  c=(c & (~(1<<n)));
  return c;
}
