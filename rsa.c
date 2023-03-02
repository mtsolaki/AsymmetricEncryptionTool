#include "rsa.h"
#include "utils.h"
/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes;

	primes =(size_t *)malloc(sizeof(size_t)*limit);
	if (primes == NULL) { 
        printf("Memory not allocated.\n"); 
        exit(0); 
    } 
	
	int i = 0, j = 0, c = 0; //counters
    double root;
	int nums[limit]; // set all numbers true (=1)
	for (i = 0; i < limit; i++)
	{
		nums[i] = 1;
	}

	root = sqrt((double)limit);
	for (i = 2; i <= root; i++)
	{
		if (nums[i] == 1)
		{
			for (j=i*i; j <= limit;  j += i)
			{
				nums[j] = 0;
			}
		}
	}
	j = 0;
	
	for (i = 0; i <= limit; i++)
	{
		if (nums[i] == 1 && i > 1)
		{	
			primes[j++] = i;
		}
	}
	j;
	*primes_sz = j;

	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	int gcde, i;
	for(i=1; i <= a && i <= b; ++i)
    {
        
        if(a%i==0 && b%i==0)
        gcde = i;
    }
	return gcde;
}





/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{	
	size_t x;
	 
    for (x=a + 1; x<b; x++) 
    {
		if ((a*x) % b == 1) 
          return x;	
	}  
}

size_t pow_mod_n(size_t x, size_t exp, size_t n)  
{  
    int res = 1;     
    x = x % n; 
   
    if (x == 0) 
	{
		return 0; 
	}
    while (exp > 0)  
    {  
        if (exp & 1)  
		{
            res = (res*x) % n;  
		}
        exp = exp/2; 
        x = (x*x) % n;  
    }  
    return res;  
}
/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	size_t *primes_array;
	int size, i;
	// find the primes
	primes_array = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &size);	
	// select two primes randomly
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
	if (fp == NULL) 
	{ 
        printf("\nFile Not Found!\n"); 
        return ; 
    } 
    fread(&p, sizeof(size_t), 1, fp);		
	p = p % size;
	p = primes_array[p];
	fclose(fp);

	fp = fopen("/dev/urandom", "r");
	if (fp == NULL) 
	{ 
        printf("\nFile Not Found!\n"); 
        return ; 
    } 
	fread(&q, sizeof(size_t), 1, fp);
	q = q % size;
	q = primes_array[q];
	fclose(fp);

	//compute n
	n = p * q;

	// compute fi_n
	fi_n = (p - 1)*(q - 1); 

	// compute e
	for (i = 0; i < size; i++)
	{
		e = primes_array[i];
		if (e % fi_n != 0 && gcd (e,fi_n) == 1 && e < fi_n)
		{
			break;
		}
	}
	
	//compute d
	d = mod_inverse(e, fi_n);
;


	fp = fopen("public.key", "w");
	fwrite(&n, 1,sizeof(size_t), fp );
	fclose(fp);

	fp = fopen("public.key", "a");
	fwrite(&d, 1,sizeof(size_t), fp );
	fclose(fp);

	fp = fopen("private.key", "w");
	fwrite(&n, 1,sizeof(size_t), fp );
	fclose(fp);

	fp = fopen("private.key", "a");
	fwrite(&e, 1,sizeof(size_t), fp );
	fclose(fp);


	free(primes_array);
 

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */

void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	
	unsigned char *plaintext = NULL;
	size_t *encrypted = NULL, p, n, e;
	int length, i;
	/* TODO */
	FILE *fp;
	size_t key[2];
	
	//read the n and e
	fp = fopen(key_file, "r");
	if (fp == NULL) 
	{ 
        printf("\nFile Not Found!\n"); 
        return ; 
    } 
	fread(key, sizeof(size_t), 2, fp);
	fclose(fp);
	n = key[0];
	e = key[1];

	//read the plaintext
	fp =fopen(input_file,"r");   
	if (fp == NULL) 
	{ 
        printf("File Not Found!\n"); 
        return; 
    } 
	fseek(fp, 0, SEEK_END);
	length = ftell(fp);
	rewind(fp);
	plaintext = (unsigned char *)malloc(sizeof(char)*length);
	fread(plaintext,sizeof(char), length, fp);
	fclose(fp);
	

	encrypted = (size_t *)malloc(sizeof(size_t)*length);
	for ( i = 0; i < length; i++)
	{
		encrypted[i]=pow_mod_n(plaintext[i], e, n);
	}
	fp = fopen(output_file, "w");
	fwrite(encrypted, length, sizeof(size_t), fp );
	fclose(fp); 

}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	size_t *ciphertext = NULL;
	int length, i;
	FILE *fp;
	size_t key[2], p, n, d;
	char *plaintext = NULL;

	// read key file
	fp = fopen(key_file, "r");
	if (fp == NULL) 
	{ 
        printf("\nFile Not Found!\n"); 
        return ; 
    } 
	fread(key, sizeof(size_t), 2, fp);
	fclose(fp);
	n = key[0];
	d = key[1];

	//read encrypted data
	fp =fopen(input_file,"r");   
	if (fp == NULL) 
	{ 
        printf("File Not Found!\n"); 
        return; 
    } 
	fseek(fp, 0, SEEK_END);
	length = ftell(fp)/8;
	rewind(fp);
	ciphertext = (size_t *)malloc(sizeof(size_t)*length);
	fread(ciphertext,sizeof(size_t), length, fp);
	fclose(fp);



	plaintext = (char *)malloc(sizeof(char)*length);
	for ( i = 0; i < length; i++)
	{	
		p =pow_mod_n(ciphertext[i], d, n);
		plaintext[i] = p;
	}

	fp = fopen(output_file, "w");
	fwrite(plaintext, length, sizeof(char), fp );
	fclose(fp); 

}
