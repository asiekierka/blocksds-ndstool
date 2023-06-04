#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ndstool.h"
#include "crc.h"

u32 card_hash[0x412];
int cardheader_devicetype = 0;
u32 global3_x00, global3_x04;	// RTC value
u32 global3_rand1;
u32 global3_rand3;

u32 lookup(u32 *magic, u32 v)
{
	u32 a = (v >> 24) & 0xFF;
	u32 b = (v >> 16) & 0xFF;
	u32 c = (v >> 8) & 0xFF;
	u32 d = (v >> 0) & 0xFF;

	a = magic[a+18+0];
	b = magic[b+18+256];
	c = magic[c+18+512];
	d = magic[d+18+768];

	return d + (c ^ (b + a));
}

void encrypt(u32 *magic, u32 *arg1, u32 *arg2)
{
	u32 a,b,c;
	a = *arg1;
	b = *arg2;
	for (int i=0; i<16; i++)
	{
		c = magic[i] ^ a;
		a = b ^ lookup(magic, c);
		b = c;
	}
	*arg2 = a ^ magic[16];
	*arg1 = b ^ magic[17];
}

void decrypt(u32 *magic, u32 *arg1, u32 *arg2)
{
	u32 a,b,c;
	a = *arg1;
	b = *arg2;
	for (int i=17; i>1; i--)
	{
		c = magic[i] ^ a;
		a = b ^ lookup(magic, c);
		b = c;
	}
	*arg1 = b ^ magic[0];
	*arg2 = a ^ magic[1];
}

void encrypt(u32 *magic, u64 &cmd)
{
	encrypt(magic, (u32 *)&cmd + 1, (u32 *)&cmd + 0);
}

void decrypt(u32 *magic, u64 &cmd)
{
	decrypt(magic, (u32 *)&cmd + 1, (u32 *)&cmd + 0);
}

void update_hashtable(u32* magic, u8 arg1[8])
{
	for (int j=0;j<18;j++)
	{
		u32 r3=0;
		for (int i=0;i<4;i++)
		{
			r3 <<= 8;
			r3 |= arg1[(j*4 + i) & 7];
		}
		magic[j] ^= r3;
	}

	u32 tmp1 = 0;
	u32 tmp2 = 0;
	for (int i=0; i<18; i+=2)
	{
		encrypt(magic,&tmp1,&tmp2);
		magic[i+0] = tmp1;
		magic[i+1] = tmp2;
	}
	for (int i=0; i<0x400; i+=2)
	{
		encrypt(magic,&tmp1,&tmp2);
		magic[i+18+0] = tmp1;
		magic[i+18+1] = tmp2;
	}
}

u32 arg2[3];

void init2(u32 *magic, u32 a[3])
{
	encrypt(magic, a+2, a+1);
	encrypt(magic, a+1, a+0);
	update_hashtable(magic, (u8*)a);
}

void init1(u32 cardheader_gamecode)
{
	u8 encr_data[0x1048];
	if(bios7filename == NULL)
	{
		fprintf(stderr, "To encrypt/decrypt the Secure Area, a copy of the NDS \"BIOS7\" must be provided.\n");
		exit(1);
	}
	else
	{
		FILE *bios7 = fopen(bios7filename, "rb");
		if(bios7 == NULL)
		{
			fprintf(stderr, "Error reading \"BIOS7\"!\n");
			exit(1);
		}
		if(fseek(bios7, 0x30, SEEK_SET))
		{
			fprintf(stderr, "Error reading \"BIOS7\"!\n");
			fclose(bios7);
			exit(1);
		}
		if(fread(encr_data, sizeof(encr_data), 1, bios7) != 1)
		{
			fprintf(stderr, "Error reading \"BIOS7\"!\n");
			fclose(bios7);
			exit(1);
		}
		fclose(bios7);
	}

	memcpy(card_hash, &encr_data, 4*(1024 + 18));
	arg2[0] = *(u32 *)&cardheader_gamecode;
	arg2[1] = (*(u32 *)&cardheader_gamecode) >> 1;
	arg2[2] = (*(u32 *)&cardheader_gamecode) << 1;
	init2(card_hash, arg2);
	init2(card_hash, arg2);
}

void init0(u32 cardheader_gamecode)
{
	init1(cardheader_gamecode);
	encrypt(card_hash, (u32*)&global3_x04, (u32*)&global3_x00);
	global3_rand1 = global3_x00 ^ global3_x04;		// more RTC
	global3_rand3 = global3_x04 ^ 0x0380FEB2;
	encrypt(card_hash, (u32*)&global3_rand3, (u32*)&global3_rand1);
}

// ARM9 decryption check values == "encr", "yObj"
#define MAGIC30		0x72636E65
#define MAGIC34		0x6A624F79

/*
 * decrypt_arm9
 */
void decrypt_arm9(u32 cardheader_gamecode, unsigned char *data)
{
	u32 *p = (u32*)data;

	init1(cardheader_gamecode);
	decrypt(card_hash, p+1, p);
	arg2[1] <<= 1;
	arg2[2] >>= 1;	
	init2(card_hash, arg2);
	decrypt(card_hash, p+1, p);

	if (p[0] != MAGIC30 || p[1] != MAGIC34)
	{
		fprintf(stderr, "Decryption failed!\n");
		exit(1);
	}

	*p++ = 0xE7FFDEFF;
	*p++ = 0xE7FFDEFF;
	u32 size = 0x800 - 8;
	while (size > 0)
	{
		decrypt(card_hash, p+1, p);
		p += 2;
		size -= 8;
	}
}

/*
 * encrypt_arm9
 */
void encrypt_arm9(u32 cardheader_gamecode, unsigned char *data)
{
	u32 *p = (u32*)data;
	if (p[0] != 0xE7FFDEFF || p[1] != 0xE7FFDEFF)
	{
		fprintf(stderr, "Encryption failed!\n");
		exit(1);
	}
	p += 2;

	init1(cardheader_gamecode);

	arg2[1] <<= 1;
	arg2[2] >>= 1;
	
	init2(card_hash, arg2);

	u32 size = 0x800 - 8;
	while (size > 0)
	{
		encrypt(card_hash, p+1, p);
		p += 2;
		size -= 8;
	}

	// place header

	p = (u32*)data;
	p[0] = MAGIC30;
	p[1] = MAGIC34;
	encrypt(card_hash, p+1, p);
	init1(cardheader_gamecode);
	encrypt(card_hash, p+1, p);
}

/*
 * EnDecryptSecureArea
 */
void EnDecryptSecureArea(char *ndsfilename, char endecrypt_option)
{
	fNDS = fopen(ndsfilename, "r+b");
	if (!fNDS) { fprintf(stderr, "Cannot open file '%s'.\n", ndsfilename); exit(1); }
	fread(&header, 512, 1, fNDS);
	int romType = DetectRomType();
	unsigned char data[0x4000];
	fseek(fNDS, 0x4000, SEEK_SET);
	fread(data, 1, 0x4000, fNDS);

	bool do_decrypt = (endecrypt_option == 'd');
	bool do_encrypt = (endecrypt_option == 'e') || (endecrypt_option == 'E');
	unsigned int rounds_offsets = (endecrypt_option == 'E') ? 0x2000 : 0x1600;
	unsigned int sbox_offsets = (endecrypt_option == 'E') ? 0x2400 : 0x1c00;

	// check if ROM is already encrypted
	if (romType == ROMTYPE_NDSDUMPED)
	{
		if (do_decrypt)
		{
			printf("Already decrypted.\n");
		}
		else 
		{
			encrypt_arm9(*(u32 *)header.gamecode, data);
			header.secure_area_crc = CalcCrc16(data, 0x4000);
			header.header_crc = CalcHeaderCRC(header);
	
			init0(*(u32 *)header.gamecode);
			srand(*(u32 *)header.gamecode);
	
			// clear data after header
			fseek(fNDS, 0x200, SEEK_SET);
			for (unsigned int i=0x200; i<0x1000; i++) fputc(0, fNDS);

/*			// random data
			fseek(fNDS, 0x1000, SEEK_SET);
			for (unsigned int i=0x1000; i<0x4000; i++) fputc(rand(), fNDS);
*/
			// rounds table
			fseek(fNDS, rounds_offsets, SEEK_SET);
			fwrite(card_hash + 0, 4, 18, fNDS);
	
			// S-boxes
			for (int i=0; i<4; i++)
			{
				fseek(fNDS, sbox_offsets + 4*256*i, SEEK_SET);
				fwrite(card_hash + 18 + i*256, 4, 256, fNDS);	// s
			}

			// test patterns
			fseek(fNDS, 0x3000, SEEK_SET);
			for (int i=0x3000; i<0x3008; i++) fputc("\xFF\x00\xFF\x00\xAA\x55\xAA\x55"[i - 0x3000], fNDS);
			for (int i=0x3008; i<0x3200; i++) fputc((u8)i, fNDS);
			for (int i=0x3200; i<0x3400; i++) fputc((u8)(0xFF-i), fNDS);
			for (int i=0x3400; i<0x3600; i++) fputc(0x00, fNDS);
			for (int i=0x3600; i<0x3800; i++) fputc(0xFF, fNDS);
			for (int i=0x3800; i<0x3A00; i++) fputc(0x0F, fNDS);
			for (int i=0x3A00; i<0x3C00; i++) fputc(0xF0, fNDS);
			for (int i=0x3C00; i<0x3E00; i++) fputc(0x55, fNDS);
			for (int i=0x3E00; i<0x4000-1; i++) fputc(0xAA, fNDS);
			fputc(0x00, fNDS);
	
			// write secure 0x800
			fseek(fNDS, 0x4000, SEEK_SET);
			fwrite(data, 1, 0x800, fNDS);
	
			// calculate CRCs and write header
			header.secure_area_crc = CalcSecureAreaCRC(false);
			header.logo_crc = CalcLogoCRC(header);
			header.header_crc = CalcHeaderCRC(header);
			fseek(fNDS, 0, SEEK_SET);
			fwrite(&header, 512, 1, fNDS);
	
			printf("Encrypted.\n");
		}
	}
	else if (romType >= ROMTYPE_ENCRSECURE)		// includes ROMTYPE_MASKROM
	{
		if (do_encrypt)
		{
			printf("Already encrypted.\n");
		}
		else
		{
			decrypt_arm9(*(u32 *)header.gamecode, data);
	
			// clear data after header
			fseek(fNDS, 0x200, SEEK_SET);
			for (unsigned int i=0x200; i<0x4000; i++) fputc(0, fNDS);
	
			// write secure 0x800
			fseek(fNDS, 0x4000, SEEK_SET);
			fwrite(data, 1, 0x800, fNDS);
	
			// write header
			fseek(fNDS, 0, SEEK_SET);
			fwrite(&header, 512, 1, fNDS);
	
			printf("Decrypted.\n");
		}
	}
	else
	{
		fprintf(stderr, "File doesn't appear to have a secure area!\n"); exit(1);
	}

	fclose(fNDS);
}
