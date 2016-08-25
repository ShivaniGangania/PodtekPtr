#define _CRT_SECURE_NO_WARNINGS
#include <WinSock2.h>
#include <memory>
using std::unique_ptr;

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include "stdafx.h"
#include "sysdep.h"
#include <time.h>
#include "uuid.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <chrono> // To print current time
#include <stdint.h>
#include "json/json.h"
#include <openssl/rand.h>

#include <cassert>
#define ASSERT assert

#pragma comment (lib, "Ws2_32.lib")

using namespace std;
using namespace Json;

int padding = RSA_PKCS1_PADDING; // Padding used for encryption
//int padding = RSA_NO_PADDING;

using BN_ptr = unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = unique_ptr<BIO, decltype(&::BIO_free)>;

/* various forward declarations */
static int read_state(unsigned16 *clockseq, uuid_time_t *timestamp,
	uuid_node_t *node);
static void write_state(unsigned16 clockseq, uuid_time_t timestamp,
	uuid_node_t node);
static void format_uuid_v1(uuid_t *uuid, unsigned16 clockseq,
	uuid_time_t timestamp, uuid_node_t node);

static void format_uuid_v3or5(uuid_t *uuid, unsigned char hash[16],
	int v);
static void get_current_time(uuid_time_t *timestamp);
static unsigned16 true_random(void);

uuid_t NameSpace_DNS = { /* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
	0x6ba7b810,
	0x9dad,
	0x11d1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};

/* uuid_create -- generator a UUID */
int uuid_create(uuid_t *uuid)
{
	uuid_time_t timestamp, last_time;
	unsigned16 clockseq;
	uuid_node_t node;
	uuid_node_t last_node;
	int f;

	/* acquire system-wide lock so we're alone */
	LOCK;
	/* get time, node ID, saved state from non-volatile storage */
	get_current_time(&timestamp);
	get_ieee_node_identifier(&node);
	f = read_state(&clockseq, &last_time, &last_node);

	/* if no NV state, or if clock went backwards, or node ID
	changed (e.g., new network card) change clockseq */
	if (!f || memcmp(&node, &last_node, sizeof node))
		clockseq = true_random();
	else if (timestamp < last_time)
		clockseq++;

	/* save the state for next time */
	write_state(clockseq, timestamp, node);

	UNLOCK;

	/* stuff fields into the UUID */
	format_uuid_v1(uuid, clockseq, timestamp, node);
	return 1;
}

/* format_uuid_v1 -- make a UUID from the timestamp, clockseq,
and node ID */
void format_uuid_v1(uuid_t* uuid, unsigned16 clock_seq,
	uuid_time_t timestamp, uuid_node_t node)
{
	/* Construct a version 1 uuid with the information we've gathered
	plus a few constants. */
	uuid->time_low = (unsigned long)(timestamp & 0xFFFFFFFF);
	uuid->time_mid = (unsigned short)((timestamp >> 32) & 0xFFFF);
	uuid->time_hi_and_version =
		(unsigned short)((timestamp >> 48) & 0x0FFF);
	uuid->time_hi_and_version |= (1 << 12);
	uuid->clock_seq_low = clock_seq & 0xFF;
	uuid->clock_seq_hi_and_reserved = (clock_seq & 0x3F00) >> 8;
	uuid->clock_seq_hi_and_reserved |= 0x80;
	memcpy(&uuid->node, &node, sizeof uuid->node);
}

/* data type for UUID generator persistent state */
typedef struct {
	uuid_time_t  ts;       /* saved timestamp */
	uuid_node_t  node;     /* saved node ID */
	unsigned16   cs;       /* saved clock sequence */
} uuid_state;

static uuid_state st;

/* read_state -- read UUID generator state from non-volatile store */
int read_state(unsigned16 *clockseq, uuid_time_t *timestamp,
	uuid_node_t *node)
{
	static int inited = 0;
	FILE *fp;

	/* only need to read state once per boot */
	if (!inited) {
		fp = fopen("state", "rb");
		if (fp == NULL)
			return 0;
		fread(&st, sizeof st, 1, fp);
		fclose(fp);
		inited = 1;
	}
	*clockseq = st.cs;
	*timestamp = st.ts;
	*node = st.node;
	return 1;
}

/* write_state -- save UUID generator state back to non-volatile
storage */
void write_state(unsigned16 clockseq, uuid_time_t timestamp,
	uuid_node_t node)
{
	static int inited = 0;
	static uuid_time_t next_save;
	FILE* fp;
	if (!inited) {
		next_save = timestamp;
		inited = 1;
	}

	/* always save state to volatile shared state */
	st.cs = clockseq;
	st.ts = timestamp;
	st.node = node;
	if (timestamp >= next_save) {
		fp = fopen("state", "wb");
		fwrite(&st, sizeof st, 1, fp);
		fclose(fp);
		/* schedule next save for 10 seconds from now */
		next_save = timestamp + (10 * 10 * 1000 * 1000);
	}
}

/* get-current_time -- get time as 60-bit 100ns ticks since UUID epoch.
Compensate for the fact that real clock resolution is
less than 100ns. */
void get_current_time(uuid_time_t *timestamp)
{
	static int inited = 0;
	static uuid_time_t time_last;
	static unsigned16 uuids_this_tick;
	uuid_time_t time_now;

	if (!inited) {
		get_system_time(&time_now);
		uuids_this_tick = UUIDS_PER_TICK;
		inited = 1;
	}

	for (; ; ) {
		get_system_time(&time_now);

		/* if clock reading changed since last UUID generated, */
		if (time_last != time_now) {
			/* reset count of uuids gen'd with this clock reading */
			uuids_this_tick = 0;
			time_last = time_now;
			break;
		}
		if (uuids_this_tick < UUIDS_PER_TICK) {
			uuids_this_tick++;
			break;
		}
		/* going too fast for our clock; spin */
	}
	/* add the count of uuids to low order bits of the clock reading */
	*timestamp = time_now + uuids_this_tick;
}

/* true_random -- generate a crypto-quality random number.
**This sample doesn't do that.** */
static unsigned16 true_random(void)
{
	static int inited = 0;
	uuid_time_t time_now;

	if (!inited) {
		get_system_time(&time_now);
		time_now = time_now / UUIDS_PER_TICK;
		srand((unsigned int)
			(((time_now >> 32) ^ time_now) & 0xffffffff));
		inited = 1;
	}

	return rand();
}

/* uuid_create_md5_from_name -- create a version 3 (MD5) UUID using a
"name" from a "name space" */
void uuid_create_md5_from_name(uuid_t *uuid, uuid_t nsid, void *name,
	int namelen)
{
	MD5_CTX c;
	unsigned char hash[16];
	uuid_t net_nsid;

	/* put name space ID in network byte order so it hashes the same
	no matter what endian machine we're on */
	net_nsid = nsid;
	net_nsid.time_low = htonl(net_nsid.time_low);
	net_nsid.time_mid = htons(net_nsid.time_mid);
	net_nsid.time_hi_and_version = htons(net_nsid.time_hi_and_version);

	MD5_Init(&c);
	MD5_Update(&c, &net_nsid, sizeof net_nsid);
	MD5_Update(&c, name, namelen);
	MD5_Final(hash, &c);

	/* the hash is in network byte order at this point */
	format_uuid_v3or5(uuid, hash, 3);
}


void uuid_create_sha1_from_name(uuid_t *uuid, uuid_t nsid, void *name, int namelen)
{
	SHA_CTX c;
	unsigned char hash[20];
	uuid_t net_nsid;

	/* put name space ID in network byte order so it hashes the same
	no matter what endian machine we're on */
	net_nsid = nsid;
	net_nsid.time_low = htonl(net_nsid.time_low);
	net_nsid.time_mid = htons(net_nsid.time_mid);
	net_nsid.time_hi_and_version = htons(net_nsid.time_hi_and_version);

	SHA1_Init(&c);
	SHA1_Update(&c, &net_nsid, sizeof net_nsid);
	SHA1_Update(&c, name, namelen);
	SHA1_Final(hash, &c);

	/* the hash is in network byte order at this point */
	format_uuid_v3or5(uuid, hash, 5);
}

/* format_uuid_v3or5 -- make a UUID from a (pseudo)random 128-bit
number */
void format_uuid_v3or5(uuid_t *uuid, unsigned char hash[16], int v)
{
	/* convert UUID to local byte order */
	memcpy(uuid, hash, sizeof *uuid);
	uuid->time_low = ntohl(uuid->time_low);
	uuid->time_mid = ntohs(uuid->time_mid);
	uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);

	/* put in the variant and version bits */
	uuid->time_hi_and_version &= 0x0FFF;
	uuid->time_hi_and_version |= (v << 12);
	uuid->clock_seq_hi_and_reserved &= 0x3F;
	uuid->clock_seq_hi_and_reserved |= 0x80;
}

/* uuid_compare --  Compare two UUID's "lexically" and return */
#define CHECK(f1, f2) if (f1 != f2) return f1 < f2 ? -1 : 1;
int uuid_compare(uuid_t *u1, uuid_t *u2)
{
	int i;

	CHECK(u1->time_low, u2->time_low);
	CHECK(u1->time_mid, u2->time_mid);
	CHECK(u1->time_hi_and_version, u2->time_hi_and_version);
	CHECK(u1->clock_seq_hi_and_reserved, u2->clock_seq_hi_and_reserved);
	CHECK(u1->clock_seq_low, u2->clock_seq_low)
		for (i = 0; i < 6; i++) {
			if (u1->node[i] < u2->node[i])
				return -1;
			if (u1->node[i] > u2->node[i])
				return 1;
		}
	return 0;
}
#undef CHECK
/* puid -- print a UUID */
void puid(uuid_t u)
{
	int i;

	printf("%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
		u.time_hi_and_version, u.clock_seq_hi_and_reserved,
		u.clock_seq_low);
	for (i = 0; i < 6; i++)
		printf("%2.2x", u.node[i]);
	printf("\n");
}
RSA * createRSA(unsigned char * key, int pub) //For encryption decryption we need to prepare RSA Struture
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	if (pub)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}

	return rsa;
}

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)//Encrypt data with public key
{
	RSA * rsa = createRSA(key, 1);
	//printf("%d\n", RSA_size(rsa) - 11);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)// Decrypt data with private key
{
	RSA * rsa = createRSA(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

void printLastError(char *msg)
{
	char * err = (char *)malloc(130);;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}


unsigned char * ReadKeyFromFile(string filename) 
{
	string line;
	string key = "";
	ifstream KeyFile(filename);
	if (KeyFile.is_open())
	{
		while (getline(KeyFile, line))
		{
			key += line + "\n";

		}
	}

	//Converting String to Char
	unsigned char *val = new unsigned char[key.length() + 1]; 
	strcpy((char *)val, key.c_str());
	return val;
}

//To print current date and time using 8601 format
const string currentDateTime() { 
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tstruct);

	return buf;
}

//To print message ID, version 4 
int uuid_v4_gen(char *buffer)
{
	union
	{
		struct
		{
			uint32_t time_low;
			uint16_t time_mid;
			uint16_t time_hi_and_version;
			uint8_t  clk_seq_hi_res;
			uint8_t  clk_seq_low;
			uint8_t  node[6];
		};
		uint8_t __rnd[16];
	} uuid;


	int rc = RAND_bytes(uuid.__rnd, sizeof(uuid));

	// Section 4.2 of RFC-4122 for reference
	uuid.clk_seq_hi_res = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
	uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

	snprintf(buffer, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
		uuid.clk_seq_hi_res, uuid.clk_seq_low,
		uuid.node[0], uuid.node[1], uuid.node[2],
		uuid.node[3], uuid.node[4], uuid.node[5]);

	return rc;
}

//To Generate the public-private key pairs
int main(int argc, char* argv[])
{
	uuid_t u;
	int f;
	char message[] = "Sample Namespace"; //to do, what namespace to choose 

	//uuid_create(&u);
	//printf("uuid_create(): "); puid(u);

    uuid_create_sha1_from_name(&u, NameSpace_DNS, message, sizeof(message));
	printf("Clinet ID is: ");//puid(u);

	char clientId[38];//UUID MAC address + username, different for every user
	snprintf(clientId, 38, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", u.time_low, u.time_mid,
		u.time_hi_and_version, u.clock_seq_hi_and_reserved,
		u.clock_seq_low, u.node[0], u.node[1],u.node[2],u.node[3],u.node[4],u.node[5]);
	cout << clientId << endl;
	//system("pause");

	/*Use it to generate 2 pairs of public-private keys*/

	//int rc_service;
	//int rc_message;

	//RSA_ptr rsa_service(RSA_new(), ::RSA_free);
	//RSA_ptr rsa_message(RSA_new(), ::RSA_free);

	//BN_ptr bn_service(BN_new(), ::BN_free);
	//BN_ptr bn_message(BN_new(), ::BN_free);


	//BIO_FILE_ptr public1(BIO_new_file("rsa-ServicePublic.pem", "w"), ::BIO_free);
	//BIO_FILE_ptr private1(BIO_new_file("rsa-ServicePrivate.pem", "w"), ::BIO_free);

	//BIO_FILE_ptr public2(BIO_new_file("rsa-MessagePublic.pem", "w"), ::BIO_free);
	//BIO_FILE_ptr private2(BIO_new_file("rsa-MessagePrivate.pem", "w"), ::BIO_free);

	//rc_service = BN_set_word(bn_service.get(), RSA_F4);
	//rc_message = BN_set_word(bn_message.get(), RSA_F4);

	//ASSERT(rc_service == 1);
	//ASSERT(rc_message == 1);

	//// Generate key
	//rc_service = RSA_generate_key_ex(rsa_service.get(), 4184, bn_service.get(), NULL);
	//rc_message = RSA_generate_key_ex(rsa_message.get(), 512, bn_message.get(), NULL);
	//ASSERT(rc_service == 1);
	//ASSERT(rc_message == 1);

	//// Convert RSA to PKEY
	//EVP_KEY_ptr pkey_service(EVP_PKEY_new(), ::EVP_PKEY_free);
	//EVP_KEY_ptr pkey_message(EVP_PKEY_new(), ::EVP_PKEY_free);

	//rc_service = EVP_PKEY_set1_RSA(pkey_service.get(), rsa_service.get());
	//rc_message = EVP_PKEY_set1_RSA(pkey_message.get(), rsa_message.get());
	//ASSERT(rc_service == 1);
	//ASSERT(rc_message == 1);

	//// Write public key1 and public key2 in Traditional PEM
	//rc_service = PEM_write_bio_PUBKEY(public1.get(), pkey_service.get());
	//rc_message = PEM_write_bio_PUBKEY(public2.get(), pkey_message.get());
	//ASSERT(rc_service == 1);
	//ASSERT(rc_message == 1);

	//// Write private key1 and private key2 in Traditional PEM
	//rc_service = PEM_write_bio_RSAPrivateKey(private1.get(), rsa_service.get(), NULL, NULL, 0, NULL, NULL);
	//rc_message = PEM_write_bio_RSAPrivateKey(private2.get(), rsa_message.get(), NULL, NULL, 0, NULL, NULL);
	//ASSERT(rc_service == 1);
	//ASSERT(rc_message == 1);

	//cout << "Your keys has been generated" << endl;

	//To read keys from file

	//unsigned char k[] = (char)key;

	string dest = "Output1.json";
	int GID = 0;   //GUID MAC address + username + time down to milisecs
	//int clientId = 1;  
	time_t curtime;
	time(&curtime);
	ofstream outFile;

	char uuidv4[38];

	int rc = uuid_v4_gen(uuidv4);

	unsigned char plainTextMessage[53] = "This is a sample PTR Message";

	unsigned char * MessagePublicKey = ReadKeyFromFile("rsa-MessagePublic.pem");
	unsigned char * MessagePrivateKey = ReadKeyFromFile("rsa-MessagePrivate.pem");
	unsigned char * ServicePublicKey = ReadKeyFromFile("rsa-ServicePublic.pem");
	unsigned char * ServicePrivateKey = ReadKeyFromFile("rsa-ServicePrivate.pem");

	unsigned char  encrypted_Message[4098] = {};
	unsigned char  encrypted_PrivateKey[4098] = {};

	unsigned char decrypted_Message[4098] = {};
	unsigned char decrypted_PrivateKey[4098] = {};

	int encrypted_length_Message = public_encrypt(plainTextMessage, strlen((char *)plainTextMessage), MessagePublicKey, encrypted_Message);
	int encrypted_length_PriKey = public_encrypt(MessagePrivateKey, strlen((char *)MessagePrivateKey), ServicePublicKey, encrypted_PrivateKey);

	if (encrypted_length_Message == -1)
	{
		printLastError("Public Encrypt failed ");
		system("pause");
		exit(0);
	}
	if (encrypted_length_PriKey == -1)
	{
		printLastError("Public Encrypt failed ");
		system("pause");
		exit(0);
	}


	printf("Encrypted_Message %s\n", encrypted_Message);
	//printf("Encrypted_PrivateKey %s\n", encrypted_PrivateKey);
	printf("Encrypted_PrivateKey %s\n",encrypted_PrivateKey);
	printf("Encrypted length =%d\n", encrypted_length_Message);

	printf("Encrypted length =%d\n", encrypted_length_PriKey);

	
	Value jsonMessage;
	jsonMessage["time"] = currentDateTime();
	jsonMessage["Message ID"] = uuidv4; //GUID
	jsonMessage["cid"] = clientId; //UUID
	jsonMessage["TimeToLive"] = 1;
	jsonMessage["message"] = reinterpret_cast< char const* >(encrypted_Message);
	jsonMessage["key"] = reinterpret_cast< char const* >(encrypted_PrivateKey);

	FastWriter jsonWriter;

	string file = jsonWriter.write(jsonMessage);
	cout << "--------------------" << endl;
	cout << file << endl;
	outFile.open(dest, ofstream::out | ofstream::app);
	if (outFile.is_open())
	{
		outFile << file;
	}
	else
	{
		cout << "Error opening file" << endl;
	}
	outFile.close();
	
	int decrypted_length_PriKey = private_decrypt(encrypted_PrivateKey, encrypted_length_PriKey, ServicePrivateKey, decrypted_PrivateKey);
	int decrypted_length_Message = 0;
	if (decrypted_length_PriKey == -1)
	{
		printLastError("Private Decrypt failed ");

	}
	else
	{
		decrypted_length_Message = private_decrypt(encrypted_Message, encrypted_length_Message, decrypted_PrivateKey, decrypted_Message);

		if (decrypted_length_Message == -1)
		{
			printLastError("Private Decrypt failed ");

		}
	}
	
	printf("Decrypted Text =%s\n", decrypted_Message);
	printf("Decrypted Text =%s\n", decrypted_PrivateKey);
	printf("Decrypted Length =%d\n", decrypted_length_Message);
	printf("Decrypted Length =%d\n", decrypted_length_PriKey);
	printf("Decrypted");

	system("pause");

	return 0;
}

