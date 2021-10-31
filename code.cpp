

#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

int main(void)
{
    FILE *fp = NULL;
    FILE *fp1 = NULL;
    int keylength;
    printf("Give a key length [only 128 or 192 or 256]:\n");
    scanf("%d", &keylength);

    unsigned char aes_key[keylength];
    memset(aes_key, 0, sizeof(aes_key));
    if (!RAND_bytes(aes_key, keylength))
    {
        exit(-1);
    }
    aes_key[keylength - 1] = '\0';

    switch (keylength)
    {
    case 128:
    {
        int choice;
        //-----------------------------------------------//
        printf("Give a encrypt or decrypt\n");
        printf("1. Encrypt \n");
        printf("2. Decrypt \n");
        printf("Choice: ");
        scanf("%d", &choice);
        //-----------------------------------------------//

        switch (choice)
        {
        case 1:
        {
            int choice1;
            printf("\n1. Enter plaintext \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//
            switch (choice1)
            {
            case 1:
            {
                unsigned char text[1000];
                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", text);

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);
                //----------------------------------------------//

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            case 2:
            {
                char text1[1000];
                fp = fopen("text.txt", "r");
                printf("Input plaintext: ");
                fgets(text1, 1000, fp);
                printf("%s", text1);
                unsigned char *text = (unsigned char *)text1;
                printf("\n");

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[128];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[128];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 128, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            }
            //---------------------------------------------//
            break;
        }

        case 2:
        {
            int choice1;
            printf("\n1. Enter ciphertext: \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//

            switch (choice1)
            {
            case 1:
            {
                unsigned char enc_out[16]; //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", enc_out);

                AES_set_decrypt_key(aes_key, 128, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }

            case 2:
            {
                //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                char enc_out1[16];
                fp = fopen("enc_out.txt", "r");
                printf("Input ciphertext: ");
                fgets(enc_out1, 1000, fp);
                printf("%s", enc_out1);
                unsigned char *enc_out = (unsigned char *)enc_out1;
                printf("\n");

                AES_set_decrypt_key(aes_key, 128, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }
            }

            break;
        }
        }

        break;
    }
    case 192:
    {
        int choice;
        //-----------------------------------------------//
        printf("Give a encrypt or decrypt\n");
        printf("1. Encrypt \n");
        printf("2. Decrypt \n");
        printf("Choice: ");
        scanf("%d", &choice);
        //-----------------------------------------------//

        switch (choice)
        {
        case 1:
        {
            int choice1;
            printf("\n1. Enter plaintext \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//
            switch (choice1)
            {
            case 1:
            {
                unsigned char text[1000];
                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", text);

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);
                //----------------------------------------------//

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[192];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[192];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[192];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[192];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[192];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[192];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            case 2:
            {
                char text1[1000];
                fp = fopen("text.txt", "r");
                printf("Input plaintext: ");
                fgets(text1, 1000, fp);
                printf("%s", text1);
                unsigned char *text = (unsigned char *)text1;
                printf("\n");

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[128];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[128];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 128, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[192];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[192];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[192];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[192];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[192];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[192];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 192, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            }
            //---------------------------------------------//
            break;
        }

        case 2:
        {
            int choice1;
            printf("\n1. Enter ciphertext: \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//

            switch (choice1)
            {
            case 1:
            {
                unsigned char enc_out[16]; //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", enc_out);

                AES_set_decrypt_key(aes_key, 192, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }

            case 2:
            {
                //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                char enc_out1[16];
                fp = fopen("enc_out.txt", "r");
                printf("Input ciphertext: ");
                fgets(enc_out1, 1000, fp);
                printf("%s", enc_out1);
                unsigned char *enc_out = (unsigned char *)enc_out1;
                printf("\n");

                AES_set_decrypt_key(aes_key, 192, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }
            }

            break;
        }
        }
        break;
    }

    case 256:
    {
        int choice;
        //-----------------------------------------------//
        printf("Give a encrypt or decrypt\n");
        printf("1. Encrypt \n");
        printf("2. Decrypt \n");
        printf("Choice: ");
        scanf("%d", &choice);
        //-----------------------------------------------//

        switch (choice)
        {
        case 1:
        {
            int choice1;
            printf("\n1. Enter plaintext \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//
            switch (choice1)
            {
            case 1:
            {
                unsigned char text[1000];
                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", text);

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);
                //----------------------------------------------//

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            case 2:
            {
                char text1[1000];
                fp = fopen("text.txt", "r");
                printf("Input plaintext: ");
                fgets(text1, 1000, fp);
                printf("%s", text1);
                unsigned char *text = (unsigned char *)text1;
                printf("\n");

                int choice2;
                printf("\n1. ECB\n");
                printf("2. CBC\n");
                printf("3. CFB\n");
                printf("4. OFB\n");
                printf("Choice: ");
                scanf("%d", &choice2);

                if (choice2 == 1)
                {
                    int sel;
                    printf("\n1. Enter key: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keyecb.txt", "r");
                        fgets(key1, 1000, fp);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes
                        AES_KEY enc_key, dec_key;  //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey: %s", &key1);
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 3:
                    {
                        /* generate a key with a given length */
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_ecb_encrypt(text, enc_out, &enc_key, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 2)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);
                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_cbc_encrypt(text, enc_out, 16, &enc_key, IV, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 3)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_cfb8_encrypt(text, enc_out, 16, &enc_key, IV, 0, 16);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                if (choice2 == 4)
                {
                    int sel;
                    printf("\n1. Enter key/IV: \n");
                    printf("2. Read from file. \n");
                    printf("3. Random key. \n");
                    printf("Choice: ");
                    scanf("%d", &sel);
                    printf("\n");
                    //---------------------------------------------------------//

                    switch (sel)
                    {
                    case 1:
                    {
                        unsigned char key[256];
                        unsigned char temp;
                        printf("Input key: ");
                        scanf("%c", &temp);
                        scanf("%[^\n]", key);
                        printf("\n");

                        unsigned char IV[256];
                        unsigned char temp1;
                        printf("Input IV: ");
                        scanf("%c", &temp1);
                        scanf("%[^\n]", IV);

                        printf("\nKey: %s", &key);
                        printf("\nIV: %s", &IV);
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));

                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    case 2:
                    {
                        char key1[256];
                        fp = fopen("keycbc.txt", "r");
                        fgets(key1, 1000, fp);
                        printf("\nKey: %s", &key1);
                        unsigned char *key = (unsigned char *)key1;
                        printf("\n");

                        char IV2[256];
                        fp1 = fopen("ivcbc.txt", "r");
                        fgets(IV2, 1000, fp1);
                        printf("\nIV: %s", &IV2);
                        unsigned char *IV = (unsigned char *)IV2;
                        printf("\n");

                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        int x;
                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));
                        break;
                    }
                    case 3:
                    {
                        unsigned char aes_key[keylength];
                        memset(aes_key, 0, sizeof(aes_key));
                        if (!RAND_bytes(aes_key, keylength))
                        {
                            exit(-1);
                        }
                        aes_key[keylength - 1] = '\0';

                        unsigned char IV[keylength];
                        memset(IV, 0, sizeof(IV));
                        if (!RAND_bytes(IV, keylength))
                        {
                            exit(-1);
                        }
                        IV[keylength - 1] = '\0';

                        int x;

                        printf("\nKey:\t");
                        for (x = 0; *(aes_key + x) != 0x00; x++)
                            printf("%X", *(aes_key + x));
                        printf("\nIV:\t");
                        for (x = 0; *(IV + x) != 0x00; x++)
                            printf("%X", *(IV + x));
                        printf("\n");
                        unsigned char enc_out[16]; //Set to 16 bytes

                        AES_KEY enc_key, dec_key; //establish AES enc and dec key

                        AES_set_encrypt_key(aes_key, 256, &enc_key);
                        AES_ofb128_encrypt(text, enc_out, 16, &enc_key, IV, 0);

                        printf("Original:\t");
                        for (x = 0; *(text + x) != 0x00; x++)
                            printf("%X ", *(text + x));
                        printf("\nEncrypted:\t");
                        for (x = 0; *(enc_out + x) != 0x00; x++)
                            printf("%X ", *(enc_out + x));

                        break;
                    }
                    }
                }

                //---------------------------------------------//

                break;
            }
            }
            //---------------------------------------------//
            break;
        }

        case 2:
        {
            int choice1;
            printf("\n1. Enter ciphertext: \n");
            printf("2. Read from file \n");
            printf("Choice: ");
            scanf("%d", &choice1);
            //---------------------------------------------//

            switch (choice1)
            {
            case 1:
            {
                unsigned char enc_out[16]; //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                unsigned char temp;
                printf("Input plaintext: ");
                scanf("%c", &temp);
                scanf("%[^\n]", enc_out);

                AES_set_decrypt_key(aes_key, 256, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }

            case 2:
            {
                //Set to 16 bytes
                unsigned char dec_out[16];

                AES_KEY enc_key, dec_key;

                char enc_out1[16];
                fp = fopen("enc_out.txt", "r");
                printf("Input ciphertext: ");
                fgets(enc_out1, 1000, fp);
                printf("%s", enc_out1);
                unsigned char *enc_out = (unsigned char *)enc_out1;
                printf("\n");

                AES_set_decrypt_key(aes_key, 256, &dec_key);
                AES_decrypt(enc_out, dec_out, &dec_key);

                int x;

                printf("\nDecrypted:\t");
                for (x = 0; *(dec_out + x) != 0x00; x++)
                    printf("%X ", *(dec_out + x));
                printf("\n");
                break;
            }
            }

            break;
        }
        }
        break;
    }
    }

    return 0;
}
