/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005, 2006 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

//#include "tpm_tspi.h"
//#include "tpm_seal.h"
//#include "tpm_unseal.h"
#include "tpmfunc.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <getopt.h>
//#include <trousers/tss.h>
//#include <trousers/trousers.h>

// From tpm_seal.h
#define TPMSEAL_HDR_STRING "-----BEGIN TSS-----\n"
#define TPMSEAL_FTR_STRING "-----END TSS-----\n"
#define TPMSEAL_TSS_STRING "-----TSS KEY-----\n"
#define TPMSEAL_EVP_STRING "-----ENC KEY-----\n"
#define TPMSEAL_ENC_STRING "-----ENC DAT-----\n"

#define TPMSEAL_KEYTYPE_SYM "Symmetric Key: "
#define TPMSEAL_CIPHER_AES256CBC "AES-256-CBC\n"

#define TPMSEAL_SECRET "password"
#define TPMSEAL_IV "IBM SEALIBM SEAL"

// From tpm_unseal.h

#define TPMSEAL_FILE_ERROR -2
#define TPMSEAL_STD_ERROR -1

enum tpm_errors {
	ENOTSSHDR = 0,
	ENOTSSFTR,
	EWRONGTSSTAG,
	EWRONGEVPTAG,
	EWRONGDATTAG,
	EWRONGKEYTYPE,
	EBADSEEK,
}; 

int tpm_errno;

int tpmUnsealFile(char*, unsigned char**, int*, int);
void tpmUnsealShred(unsigned char*, int);

int hashPassword(const char*, size_t, BYTE*);

void shredPasswd(char* passwd){
	tpmUnsealShred((unsigned char*) passwd, strlen(passwd));
}

// From tpm_utils.c
char *_getPasswd(const char *a_pszPrompt, int* a_iLen,
		int a_bConfirm) {

	char *pszPrompt = (char *)a_pszPrompt;
	char *pszPasswd = NULL;
	char *pszRetPasswd = NULL;

	do {
		// Get password value from user - this is a static buffer
		// and should never be freed
		pszPasswd = getpass( pszPrompt );
		if (!pszPasswd && pszRetPasswd) {
			shredPasswd( pszRetPasswd );
			return NULL;
		}

		// If this is confirmation pass check for match
		if ( pszRetPasswd ) {
			// Matched work complete
			if ( strcmp( pszPasswd, pszRetPasswd ) == 0)
				goto out;

			// No match clean-up
			fprintf(stderr,"Passwords didn't match\n");

			// pszPasswd will be cleaned up at out label
			shredPasswd( pszRetPasswd );
			pszRetPasswd = NULL;
			goto out;
		}

		// Save this passwd for next pass and/or return val
		pszRetPasswd = strdup( pszPasswd );
		if ( !pszRetPasswd )
			goto out;

		pszPrompt = "Confirm password: ";
	} while (a_bConfirm);

out:
	if (pszRetPasswd) {
		*a_iLen = strlen(pszRetPasswd);

	}

	// pszPasswd is a static buffer, just clear it
	if ( pszPasswd )
		memset( pszPasswd, 0, strlen( pszPasswd ) );

	return pszRetPasswd;
}


/*
enum tspi_errors {
	ETSPICTXCREAT = 0,
	ETSPICTXCNCT,
	ETSPICTXCO,
	ETSPICTXLKBU,
	ETSPICTXLKBB,
	ETSPISETAD,
	ETSPIGETPO,
	ETSPIPOLSS,
	ETSPIDATU,
	ETSPIPOLATO,
};

TSS_HCONTEXT hContext = 0;
#define TSPI_FUNCTION_NAME_MAX 30
char tspi_error_strings[][TSPI_FUNCTION_NAME_MAX]= {
				"Tspi_Context_Create",
				"Tspi_Context_Connect",
				"Tspi_Context_CreateObject",
				"Tspi_Context_LoadKeyByUUID",
				"Tspi_Context_LoadKeyByBlob",
				"Tspi_SetAttribData",
				"Tspi_GetPolicyObject",
				"Tspi_Policy_SetSecret",
				"Tspi_Data_Unseal",
				"Tspi_Policy_AssignToObject",
};
*/

#define TSSKEY_DEFAULT_SIZE 768
#define EVPKEY_DEFAULT_SIZE 512

//int tpm_errno;

int hashPassword(const char* pass, size_t pass_len, BYTE* digest){
	int rc=-1;
	EVP_MD_CTX *mdctx;
	

	// TODO: return the error codes, if needed

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(mdctx, pass, pass_len);
	//*digest = OPENSSL_malloc(EVP_MD_size(EVP_sha1()));
	EVP_DigestFinal_ex(mdctx, digest, NULL);

	rc=0;
hash_out:
	EVP_MD_CTX_destroy(mdctx);
	return rc;
}

int tpmUnsealFile( char* fname, unsigned char** tss_data, int* tss_size,
		   int srkWellKnown ) {

	int rc, rcLen=0, tssLen=0, evpLen=0;
	BYTE* rcPtr;
	char data[EVP_CIPHER_block_size(EVP_aes_256_cbc()) * 16];
	BYTE *tssKeyData = NULL;
	int tssKeyDataSize = 0;
	BYTE *evpKeyData = NULL;
	int evpKeyDataSize = 0;
	struct stat stats;
	//TSS_HENCDATA hEncdata;
	//TSS_HKEY hSrk, hKey;
	//TSS_HPOLICY hPolicy;
	uint32_t symKeyLen = 0;
	BYTE *symKey = 0;
	BYTE srkauth[TPM_HASH_SIZE] = {0};
	BYTE dataauth[TPM_HASH_SIZE];
	char *srkSecret = NULL;
	int srkSecretLen;
	unsigned char* res_data = NULL;
	int res_size = 0;

	BIO *bdata = NULL, *b64 = NULL, *bmem = NULL;
	int bioRc = 0;

	if ( tss_data == NULL || tss_size == NULL ) {
		rc = TPMSEAL_STD_ERROR;
		tpm_errno = EINVAL;
		goto out;
	}

	*tss_data = NULL;
	*tss_size = 0;

	/* Test for file existence */
	if ((rc = stat(fname, &stats))) {
		tpm_errno = errno;
		goto out;
	}

	/* Create an input file BIO */
	if((bdata = BIO_new_file(fname, "r")) == NULL ) {
		tpm_errno = errno;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	/* Test file header for TSS */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_HDR_STRING,
			strlen(TPMSEAL_HDR_STRING)) != 0) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = ENOTSSHDR;
		goto out;
	}

	/* Looking for TSS Key Header */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_TSS_STRING,
			strlen(TPMSEAL_TSS_STRING)) != 0) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGTSSTAG;
		goto out;
	}

	/* Create a memory BIO to hold the base64 TSS key */
	if ((bmem = BIO_new(BIO_s_mem())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}
	BIO_set_mem_eof_return(bmem, 0);

	/* Read the base64 TSS key into the memory BIO */
	while ((rcLen = BIO_gets(bdata, data, sizeof(data))) > 0) {
		/* Look for EVP Key Header (end of key) */
		if (strncmp(data, TPMSEAL_EVP_STRING,
				strlen(TPMSEAL_EVP_STRING)) == 0)
			break;

		if (BIO_write(bmem, data, rcLen) <= 0) {
			tpm_errno = EIO;
			rc = TPMSEAL_STD_ERROR;
			goto out;
		}
	}
	if (strncmp(data, TPMSEAL_EVP_STRING,
			strlen(TPMSEAL_EVP_STRING)) != 0 ) {
		tpm_errno = EWRONGEVPTAG;
		rc = TPMSEAL_FILE_ERROR;
		goto out;
	}

	/* Create a base64 BIO to decode the TSS key */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	/* Decode the TSS key */
	bmem = BIO_push( b64, bmem );
	while ((rcLen = BIO_read(bmem, data, sizeof(data))) > 0) {
		if ((tssLen + rcLen) > tssKeyDataSize) {
			tssKeyDataSize += TSSKEY_DEFAULT_SIZE;
			rcPtr = realloc( tssKeyData, tssKeyDataSize);
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = TPMSEAL_STD_ERROR;
				goto out;
			}
			tssKeyData = rcPtr;
		}
		memcpy(tssKeyData + tssLen, data, rcLen);
		tssLen += rcLen;
	}
	bmem = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;
	bioRc = BIO_reset(bmem);
	if (bioRc != 1) {
		tpm_errno = EIO;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	/* Check for EVP Key Type Header */
	BIO_gets(bdata, data, sizeof(data));
	if (strncmp(data, TPMSEAL_KEYTYPE_SYM,
			strlen(TPMSEAL_KEYTYPE_SYM)) != 0 ) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGKEYTYPE;
		goto out;
	}

	/* Make sure it's a supported cipher
	   (currently only AES 256 CBC) */
	if (strncmp(data + strlen(TPMSEAL_KEYTYPE_SYM),
			TPMSEAL_CIPHER_AES256CBC,
			strlen(TPMSEAL_CIPHER_AES256CBC)) != 0) {
		rc = TPMSEAL_FILE_ERROR;
		tpm_errno = EWRONGKEYTYPE;
		goto out;
	}

	/* Read the base64 Symmetric key into the memory BIO */
	while ((rcLen = BIO_gets(bdata, data, sizeof(data))) > 0) {
		/* Look for Encrypted Data Header (end of key) */
		if (strncmp(data, TPMSEAL_ENC_STRING,
				strlen(TPMSEAL_ENC_STRING)) == 0)
			break;

		if (BIO_write(bmem, data, rcLen) <= 0) {
			tpm_errno = EIO;
			rc = TPMSEAL_STD_ERROR;
			goto out;
		}
	}
	if (strncmp(data, TPMSEAL_ENC_STRING,
			strlen(TPMSEAL_ENC_STRING)) != 0 ) {
		tpm_errno = EWRONGDATTAG;
		rc = TPMSEAL_FILE_ERROR;
		goto out;
	}

	/* Create a base64 BIO to decode the Symmetric key */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	/* Decode the Symmetric key */
	bmem = BIO_push( b64, bmem );
	while ((rcLen = BIO_read(bmem, data, sizeof(data))) > 0) {
		if ((evpLen + rcLen) > evpKeyDataSize) {
			evpKeyDataSize += EVPKEY_DEFAULT_SIZE;
			rcPtr = realloc( evpKeyData, evpKeyDataSize);
			if ( rcPtr == NULL ) {
				tpm_errno = ENOMEM;
				rc = TPMSEAL_STD_ERROR;
				goto out;
			}
			evpKeyData = rcPtr;
		}
		memcpy(evpKeyData + evpLen, data, rcLen);
		evpLen += rcLen;
	}
	bmem = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;
	bioRc = BIO_reset(bmem);
	if (bioRc != 1) {
		tpm_errno = EIO;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

	/* Read the base64 encrypted data into the memory BIO */
	while ((rcLen = BIO_gets(bdata, data, sizeof(data))) > 0) {
		/* Look for TSS Footer (end of data) */
		if (strncmp(data, TPMSEAL_FTR_STRING,
				strlen(TPMSEAL_FTR_STRING)) == 0)
			break;

		if (BIO_write(bmem, data, rcLen) <= 0) {
			tpm_errno = EIO;
			rc = TPMSEAL_STD_ERROR;
			goto out;
		}
	}
	if (strncmp(data, TPMSEAL_FTR_STRING,
			strlen(TPMSEAL_FTR_STRING)) != 0 ) {
		tpm_errno = ENOTSSFTR;
		rc = TPMSEAL_FILE_ERROR;
		goto out;
	}

	/* First, hash the data password (by default "password") to get the
	 * dataauth password.  Note that this uses SHA1, but we can use openSSL here.
	 */

	if(hashPassword(TPMSEAL_SECRET,strlen(TPMSEAL_SECRET),dataauth)){
		rc=TPMSEAL_STD_ERROR;
		goto out;
	}
	
	/* Now, if needed, hash the srk password to get the keyauth password
	 * (NOTE: we REALLY should be using the well-known secret)
	 */
	if (!srkWellKnown) {
		/* Prompt for SRK password */
		srkSecret = _getPasswd("Enter SRK password: ", &srkSecretLen, FALSE);
		if(!srkSecret || hashPassword(srkSecret, srkSecretLen, srkauth)){
			rc=TPMSEAL_STD_ERROR;
			goto out;
		}
	}

	/* allocate some memory for the raw data */
	symKey = malloc(evpLen);

	/* unseal using the SRK */
	if ((rc=TPM_Unseal(0x40000000, srkauth, dataauth, evpKeyData, evpLen, symKey, &)) != 0){
		tpm_errno = TPMSEAL_STD_ERROR;
		goto tss_out;
	}

	/*
	if ((rc=Tspi_Data_Unseal(hEncdata, hKey, &,
					&symKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPIDATU;
		goto tss_out;
	}

	* Unseal
	if ((rc=Tspi_Context_Create(&hContext)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCREAT;
		goto out;
	}


	if ((rc=Tspi_Context_Connect(hContext, NULL)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCNCT;
		goto tss_out;
	}

	if ((rc=Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_ENCDATA,
					TSS_ENCDATA_SEAL,
					&hEncdata)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCO;
		goto tss_out;
	}

	if ((rc=Tspi_SetAttribData(hEncdata,
				TSS_TSPATTRIB_ENCDATA_BLOB,
				TSS_TSPATTRIB_ENCDATABLOB_BLOB,
				evpLen, evpKeyData)) != TSS_SUCCESS) {
		tpm_errno = ETSPISETAD;
		goto tss_out;
	}

	if ((rc=Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE,
					&hPolicy)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCO;
		goto tss_out;
	}

	if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN,
					strlen(TPMSEAL_SECRET),
					(BYTE *)TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out;
	}

	if ((rc=Tspi_Policy_AssignToObject(hPolicy, hEncdata)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLATO;
		goto tss_out;
	}

	if ((rc=Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					SRK_UUID, &hSrk)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBU;
		goto tss_out;
	}

	* Don't create a new policy for the SRK's secret, just use the context's
	 * default policy 
	if ((rc=Tspi_GetPolicyObject(hSrk, TSS_POLICY_USAGE,
					&hPolicy)) != TSS_SUCCESS){
		tpm_errno = ETSPIGETPO;
		goto tss_out;
	}

	if (srkWellKnown)
		rc = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
				           sizeof(wellKnown),
				           (BYTE *) wellKnown);
	else
		rc = Tspi_Policy_SetSecret(hPolicy,TSS_SECRET_MODE_PLAIN,
					   srkSecretLen,
					   (BYTE *) srkSecret);

	if (rc != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out;
	}

	* Failure point if trying to unseal data on a differnt TPM
	if ((rc=Tspi_Context_LoadKeyByBlob(hContext, hSrk, tssLen,
					tssKeyData, &hKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXLKBB;
		goto tss_out;
	}

	if ((rc=Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE,
					&hPolicy)) != TSS_SUCCESS) {
		tpm_errno = ETSPICTXCO;
		goto tss_out;
	}

	if ((rc=Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN,
					strlen(TPMSEAL_SECRET),
					(BYTE *)TPMSEAL_SECRET)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLSS;
		goto tss_out;
	}

	if ((rc=Tspi_Policy_AssignToObject(hPolicy, hKey)) != TSS_SUCCESS) {
		tpm_errno = ETSPIPOLATO;
		goto tss_out;
	}

	*/

	/* Malloc a block of storage to hold the decrypted data
	   Using the size of the mem BIO is more than enough
	   (plus an extra cipher block size) */
	res_data = malloc(BIO_pending(bmem) + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
	if ( res_data == NULL ) {
		rc = TPMSEAL_STD_ERROR;
		tpm_errno = ENOMEM;
		goto tss_out;
	}

	/* Decode and decrypt the encrypted data */
	EVP_CIPHER_CTX ctx;
	EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), symKey, (unsigned char *)TPMSEAL_IV);

	/* Create a base64 BIO to decode the encrypted data */
	if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
		tpm_errno = EAGAIN;
		rc = TPMSEAL_STD_ERROR;
		goto tss_out;
	}

	bmem = BIO_push( b64, bmem );
	while ((rcLen = BIO_read(bmem, data, sizeof(data))) > 0) {
		EVP_DecryptUpdate(&ctx, res_data+res_size,
					&rcLen, (unsigned char *)data, rcLen);
		res_size += rcLen;
	}
	EVP_DecryptFinal(&ctx, res_data+res_size, &rcLen);
	res_size += rcLen;
	bmem = BIO_pop(b64);
	BIO_free(b64);
	b64 = NULL;
	/* a BIO_reset failure shouldn't have an affect at this point */
	bioRc = BIO_reset(bmem);
	if (bioRc != 1) {
		tpm_errno = EIO;
		rc = TPMSEAL_STD_ERROR;
		goto out;
	}

tss_out:
	//Tspi_Context_Close(hContext);
out:

	/* shred the srk secret and the symKey */
	if (srkSecret)
		tpmUnsealShred((unsigned char *) srkSecret, strlen(srkSecret));

	if(symKey)
		tpmUnsealShred(symKey, evpLen);

	if ( bdata )
		BIO_free(bdata);
	if ( b64 )
		BIO_free(b64);
	if ( bmem ) {
		bioRc = BIO_set_close(bmem, BIO_CLOSE);
		BIO_free(bmem);
	}

	if (bioRc != 1) {
		tpm_errno = EIO;
		rc = TPMSEAL_STD_ERROR;
	}

	if ( evpKeyData )
		free(evpKeyData);
	if ( tssKeyData )
		free(tssKeyData);

	if ( rc == 0 ) {
		*tss_data = res_data;
		*tss_size = res_size;
	} else
		free(res_data);

	return rc;
}

void tpmUnsealShred(unsigned char* data, int size) {
	if ( data != NULL ) {
		memset( data, 0, size);
		free(data);
	}
}

static void help(const char *aCmd)
{
	fprintf(stdout, "Usage: %s [options]\n", aCmd);
	fprintf(stdout,"\t%s\n\t\t%s\n",
		"-i, --infile FILE","Filename containing data to unseal." );
	fprintf(stdout,"\t%s\n\t\t%s\n",
		"-o, --outfile FILE","Filename to write unsealed data to.  Default is STDOUT.");
	fprintf(stdout,"\t%s\n\t\t%s\n",
		"-z, --srk-well-known","Use 20 bytes of zeros (TSS_WELL_KNOWN_SECRET) as the SRK secret.");
}

static char in_filename[PATH_MAX] = "", out_filename[PATH_MAX] = "";
static int srkWellKnown = 0;

static int parse(const int aOpt, const char *aArg)
{
	int rc = -1;

	switch (aOpt) {
	case 'i':
		if (aArg) {
			strncpy(in_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'o':
		if (aArg) {
			strncpy(out_filename, aArg, PATH_MAX);
			rc = 0;
		}
		break;
	case 'z':
		srkWellKnown = 1;
		rc = 0;
		break;
	default:
		break;
	}
	return rc;

}

int main(int argc, char **argv)
{

	struct option opts[] =
	    { {"infile", required_argument, NULL, 'i'},
	      {"outfile", required_argument, NULL, 'o'},
	      {"srk-well-known", no_argument, NULL, 'z'},
	      {0,0,0,0}
	};
	FILE *fp;
	int rc=0, tss_size=0, i;
	unsigned char* tss_data = NULL;
	int c;

	while (1){
		int opt_index=0;
		c = getopt_long(argc, argv, "i:o:z", opts, &opt_index);

		if(c==-1)
			break;

		if(parse(c, optarg) != 0){
			help(argv[0]);
			return rc;
		}
	}
	
	rc = tpmUnsealFile(in_filename, &tss_data, &tss_size, srkWellKnown);

	if (strlen(out_filename) == 0) {
		for (i=0; i < tss_size; i++)
			printf("%c", tss_data[i]);
		goto out;
	} else if ((fp = fopen(out_filename, "w")) == NULL) {
			fprintf(stderr, "Unable to open output file\n");
			goto out;
	}

	if (fwrite(tss_data, tss_size, 1, fp) != 1) {
		fprintf(stderr, "Unable to write output file\n");
		goto out;
	}
	fclose(fp);
out:
	free(tss_data);
	return rc;
}
