#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <regex.h>
#include <nfc/nfc.h>
#include <freefare.h>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

// old : Mifare sectors 10 -> 14
#define START_SECTOR     8
#define NBR_SECTOR       4
#define HEADER_OFFSET    0
#define DATAA_OFFSET    48
#define DATAB_OFFSET   112
#define FOOTER_OFFSET  176

#define CRC16 0x8005

MifareClassicKey keys[] = {
	{ 0xff,0xff,0xff,0xff,0xff,0xff },  // Classics NFC keys...
	{ 0xa0,0xb0,0xc0,0xd0,0xe0,0xf0 },
	{ 0xa1,0xb1,0xc1,0xd1,0xe1,0xf1 },
	{ 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
	{ 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
	{ 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
	{ 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
	{ 0x00,0x00,0x00,0x00,0x00,0x00 },
	{ 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
	{ 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
	{ 0x41,0x5a,0x54,0x45,0x4b,0x4d },  // self-service laundry
};

struct keymap {
	int prout;
	MifareClassicKey *keyA;
	MifareClassicKey *keyB;
	uint16_t readA;
	uint16_t readB;
	uint16_t writeA;
	uint16_t writeB;
};

int bcd2bin(uint8_t val) {
	return( (((val & 0xf0) >> 4)*10) + (val & 0x0f) );
}

// read data from tag
int readlavtag(MifareTag *tags, uint8_t *dest, int verb)
{
	int i,k;
	MifareClassicBlock data;

	for(i=START_SECTOR; i<(START_SECTOR+NBR_SECTOR); i++) {
		if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
					(mifare_classic_authenticate(tags[0],
												 mifare_classic_sector_last_block(i),
												 keys[0],
												 MFC_KEY_B) == OPERATION_OK)) {
			for(k=mifare_classic_sector_first_block(i); k<mifare_classic_sector_last_block(i); k++) {
				if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
					if(verb)
						printf("read sector %d block %d\n", i, k);
					memcpy(dest+(16*(k%4)+48*(i-START_SECTOR)), data, 16);
				} else {
					fprintf(stderr, "read error: %s\n", freefare_strerror(tags[0]));
					return(1);
				}
			}
			mifare_classic_disconnect(tags[0]);
		} else {
			fprintf(stderr, "Auth error ! Abord ! Abord ! Abord !\n");
			mifare_classic_disconnect(tags[0]);
			return(1);
		}
	}
	return(0);
}

// copy data to tag
int writelavtag(MifareTag *tags, uint8_t *src, int verb)
{
	int i,k;
	MifareClassicBlock data;

	for(i=START_SECTOR; i<(START_SECTOR+NBR_SECTOR); i++) {
		if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
					(mifare_classic_authenticate(tags[0],
												 mifare_classic_sector_last_block(i),
												 keys[0],
												 MFC_KEY_B) == OPERATION_OK)) {
			for(k=mifare_classic_sector_first_block(i); k<mifare_classic_sector_last_block(i); k++) {
				memcpy(data, src+(16*(k%4)+48*(i-START_SECTOR)), 16);
				if(mifare_classic_write(tags[0], k, data) == OPERATION_OK) {
					if(verb)
						printf("write sector %d block %d\n", i, k);
				} else {
					fprintf(stderr, "write error: %s\n", freefare_strerror(tags[0]));
					return(1);
				}
			}
			mifare_classic_disconnect(tags[0]);
		} else {
			fprintf(stderr, "Auth error ! Abord ! Abord ! Abord !\n");
			mifare_classic_disconnect(tags[0]);
			return(1);
		}
	}
	return(0);
}

// read array and fill file
int writefile(const char *filename, uint8_t *src, int num)
{
	FILE *fp;

	fp = fopen(filename, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Error opening file: %s\n", strerror(errno));
		return(1);
	}
	if(fwrite(src, sizeof(uint8_t), num, fp) != num) {
		fprintf(stderr, "Error writing file: %s\n", strerror(errno));
		return(1);
	}

	return(0);
}

// read file and fill array
int readfile(const char *filename, uint8_t *dest, int num)
{
	FILE *fp;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error opening file: %s\n", strerror(errno));
		return(1);
	}
	if(fread(dest, sizeof(uint8_t), num, fp) != num) {
		fprintf(stderr, "Error reading file: %s\n", strerror(errno));
		return(1);
	}
	return(0);
}

void printhelp(char *binname)
{
	printf("RFID Mifare Laundry card reader/writer v0.0.1\n");
	printf("Copyright (c) 2019 - Denis Bodor\n\n");
	printf("Usage : %s [OPTIONS]\n", binname);
	printf(" -r file     read data from file (default: read from tag)\n");
	printf(" -w file     write data to file (filename will be file.UID)\n");
	printf(" -y          force file overwrite\n");
	printf(" -c float    new credit to set\n");
	printf(" -u          update tag (use with -c)\n");
	printf(" -v          verbose mode\n");
	printf(" -h          show this help\n");
}

int maptag(MifareTag *tags, struct keymap *myKM, int nbrsect)
{
	int i, j, k;
	int count = 0;

	for(i=0; i<nbrsect; i++) {
		for(j=0; j < sizeof(keys)/sizeof(keys[0]); j++) {
			if(myKM[i].keyA == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), keys[j], MFC_KEY_A) == OPERATION_OK) {
					//printf("sector %02d auth with key A[%d]=%02x%02x%02x%02x%02x%02x\n", i, j, keys[j][0],keys[j][1],keys[j][2],keys[j][3],keys[j][4],keys[j][5]);
					myKM[i].keyA = &keys[j];
					count++;
					for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
						if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_A)) {
							myKM[i].readA |= (1 << (k-mifare_classic_sector_first_block(i)));
						}
						// is keyB readable ? If so, keyB cannot be used for auth
						if(!mifare_classic_get_trailer_block_permission(tags[0], mifare_classic_sector_last_block(i), MCAB_READ_KEYB, MFC_KEY_A)) {
							if(mifare_classic_get_data_block_permission(tags[0], k, MCAB_R, MFC_KEY_B)) {
								myKM[i].readB |= (1 << (k-mifare_classic_sector_first_block(i)));
							}
						}
					}
				}
				mifare_classic_disconnect(tags[0]);
			}

			if(myKM[i].keyB == NULL) {
				if(mifare_classic_connect(tags[0]) == OPERATION_OK &&
						mifare_classic_authenticate(tags[0], mifare_classic_sector_last_block(i), keys[j], MFC_KEY_B) == OPERATION_OK) {
					//printf("sector %02d auth with key B[%d]=%02x%02x%02x%02x%02x%02x\n", i, j, keys[j][0],keys[j][1],keys[j][2],keys[j][3],keys[j][4],keys[j][5]);
					myKM[i].keyB = &keys[j];
					count++;
					//if(mifare_classic_get_data_block_permission(tags[0], mifare_classic_sector_first_block(i), MCAB_R, MFC_KEY_A)) printf("A");
					//if(mifare_classic_get_data_block_permission(tags[0], mifare_classic_sector_first_block(i), MCAB_R, MFC_KEY_B)) printf("B");
				}
				mifare_classic_disconnect(tags[0]);
			}
			if(myKM[i].keyA && myKM[i].keyB) break;
		}
		printf("Mapping: %d/%d\r", i, nbrsect);
		fflush(stdout);
	}

	if(count != nbrsect*2)
		return(-1);

	return(0);
}

void printmapping(struct keymap *myKM, int nbrsect)
{
	// struct keymap myKM[40]
	int countkeys = 0;
	int i;

	printf("        key A         key B         ReadA    ReadB\n");
	for(i=0; i<nbrsect; i++) {
		MifareClassicKey *tmpkeyA = myKM[i].keyA;
		MifareClassicKey *tmpkeyB = myKM[i].keyB;

		printf("%02d:  ", i);
		if(tmpkeyA != NULL)
			printf("%02x%02x%02x%02x%02x%02x", (*tmpkeyA)[0],(*tmpkeyA)[1],(*tmpkeyA)[2],(*tmpkeyA)[3],(*tmpkeyA)[4],(*tmpkeyA)[5]);
		else
			printf("------------");
		if(tmpkeyB != NULL)
			printf("  %02x%02x%02x%02x%02x%02x", (*tmpkeyB)[0],(*tmpkeyB)[1],(*tmpkeyB)[2],(*tmpkeyB)[3],(*tmpkeyB)[4],(*tmpkeyB)[5]);
		else
			printf("  ------------");
		printf("     %04X", myKM[i].readA);
		printf("     %04X", myKM[i].readB);
		printf("\n");
	}

	for(i=0; i<nbrsect; i++) {
		countkeys += myKM[i].keyA == NULL ? 0 : 1;
		countkeys += myKM[i].keyB == NULL ? 0 : 1;
	}
	if(countkeys == nbrsect*2)
		printf("Found all keys (%d)\n", countkeys);
	else
		printf("Keymap incomplete: %d/%d\n", countkeys, (nbrsect*2));
}

void printblock(MifareClassicBlock *data)
{
	for(int i=0; i<16; i++)
		printf("%02X", (*data)[i]);
	printf("\n");
}

int readtag(MifareTag *tags, struct keymap *myKM, int nbrsect)
{
	int i, k;
	MifareClassicKey *tmpkeyA;
	MifareClassicKey *tmpkeyB;
	MifareClassicBlock data;

	for(i=0; i<nbrsect; i++) {
		tmpkeyA = myKM[i].keyA;
		tmpkeyB = myKM[i].keyB;
		printf("+Sector %d:\n", i);
		// read sector block by block, check if we have keys
		for(k=mifare_classic_sector_first_block(i); k <= mifare_classic_sector_last_block(i); k++) {
			if(myKM[i].readB & (1 << (k-mifare_classic_sector_first_block(i))) && tmpkeyB != NULL) {
				if(tmpkeyB != NULL) {
					if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
							(mifare_classic_authenticate(tags[0],
														 k,
														 *tmpkeyB,
														 MFC_KEY_B) == OPERATION_OK)) {
						if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
							printblock(&data);
						} else {
							fprintf(stderr, "read error: %s\n", freefare_strerror(tags[0]));
						}
						mifare_classic_disconnect(tags[0]);
					} else {
						fprintf(stderr, "Auth error !\n");
						mifare_classic_disconnect(tags[0]);
					}
				}
			} else if(myKM[i].readA & (1 << (k-mifare_classic_sector_first_block(i))) && tmpkeyA != NULL){
				if(tmpkeyA != NULL) {
					if((mifare_classic_connect(tags[0]) == OPERATION_OK) &&
							(mifare_classic_authenticate(tags[0],
														 k,
														 *tmpkeyA,
														 MFC_KEY_A) == OPERATION_OK)) {
						if(mifare_classic_read(tags[0], k, &data) == OPERATION_OK) {
							printblock(&data);
						} else {
							fprintf(stderr, "read error: %s\n", freefare_strerror(tags[0]));
						}
						mifare_classic_disconnect(tags[0]);
					} else {
						fprintf(stderr, "Auth error !\n");
						mifare_classic_disconnect(tags[0]);
					}
				}
			} else {
				// FIXME key missing for this block
				printf("-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --\n");
			}
		}
	}
	return(0);
}

int main(int argc, char** argv)
{
	nfc_context *context;
	nfc_device *pnd = NULL;
	MifareTag *tags = NULL;

	int nbrsect;

	int retopt;
	int opt = 0;
	char *endptr;

	int verb = 0;
	int updatetag = 0;
	int foverwrite = 0;
	char *wfilename = NULL;
	char *rfilename = NULL;
	char fnbuffer[256];
	char exbuffer[9] = { 0 };
	regex_t regex;

	// we don't store keys, but pointers to key in keyslist
	struct keymap myKM[40] = {{ 42, NULL, NULL, 0, 0, 0, 0 }};

	while ((retopt = getopt(argc, argv, "r:w:c:uvyh")) != -1) {
		switch (retopt) {
			case 'r':
				if(regcomp(&regex, "\\.[a-fA-F0-9]{8}$", REG_EXTENDED)) {
					fprintf(stderr, "Error: Enable to compile regex\n");
					return(EXIT_FAILURE);
				}
				rfilename = strdup(optarg);
				if(regexec(&regex, rfilename, 0, NULL, 0) != 0) {
					fprintf(stderr, "Error: filename must have valid UID extension (exemple : file.54D27CC8)\n");
					return(EXIT_FAILURE);
				}
				opt++;
				break;
			case 'w':
				if(sizeof(optarg)+8+1 > sizeof(fnbuffer)) {
					fprintf(stderr, "Invalid filename\n");
					return(EXIT_FAILURE);
				}
				wfilename = strdup(optarg);
				opt++;
				break;
			case 'c':
//				fcredit = strtof(optarg, &endptr);
//				if (endptr == optarg) {
//					fprintf(stderr, "You must specify a valid credit value\n");
//					return(EXIT_FAILURE);
//				}
				opt++;
				break;
			case 'u':
				updatetag = 1;
				opt++;
				break;
			case 'v':
				verb = 1;
				opt++;
				break;
			case 'y':
				foverwrite = 1;
				opt++;
				break;
			case 'h':
				printhelp(argv[0]);
				return(EXIT_SUCCESS);
			default:
				printhelp(argv[0]);
				return(EXIT_FAILURE);
		}
	}


	// Initialize libnfc and set the nfc_context
	nfc_init(&context);
	if (context == NULL) {
		fprintf(stderr, "Unable to init libnfc\n");
		exit(EXIT_FAILURE);
	}

	// Open, using the first available NFC device
	pnd = nfc_open(context, NULL);

	if (pnd == NULL) {
		fprintf(stderr, "Error: %s\n", "Unable to open NFC device.");
		exit(EXIT_FAILURE);
	}

	printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

	tags = freefare_get_tags(pnd);

	if(!tags[0] || !tags) {
		fprintf(stderr, "no valid tag found !\n");
		nfc_close(pnd);
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	switch(freefare_get_tag_type(tags[0])) {
		case CLASSIC_1K:
			printf("%u : Mifare 1k (S50) with UID: %s\n", 0, freefare_get_tag_uid(tags[0]));
			nbrsect = 16;  // 16 sectors * 4 bloks
			break;
		case CLASSIC_4K:
			printf("%u : Mifare 4k (S70) with UID: %s\n", 0, freefare_get_tag_uid(tags[0]));
			nbrsect = 40;  // 32 sectors * 4 blocks + 8 sector * 16 blocks
			break;
		default:
			fprintf(stderr, "no Mifare 1k (S50) or 4k (S70) tag found !\n");
			nfc_close(pnd);
			nfc_exit(context);
			exit(EXIT_FAILURE);
	}

	//mfuid = strtol(freefare_get_tag_uid(tags[0]), NULL, 16) & 0xffffffff;

	if(maptag(tags, myKM, nbrsect) != 0)
		printf("Warning: missing keys !\n");

	printmapping(myKM, nbrsect);

	readtag(tags, myKM, nbrsect);

	freefare_free_tags(tags);
	// Close NFC device
	nfc_close(pnd);
	// Release the context
	nfc_exit(context);

	exit(EXIT_SUCCESS);
}
