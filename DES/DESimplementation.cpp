/*
Algorithm : Data Encryption Standard
Date: 20/07/2016
Implemented By: Mohammad Sheikh Ghazanfar
                CSE(Ongoing),
                International Islamic University Chittagong
*/

#include <iostream>
#include <algorithm>
#include <vector>
#include <map>
#include <bitset>

using namespace std;

#define f(i,j,n) for(int i=j; i<n; i++)  //This is the only macro used here in order to make the code(for specifically looping) easier .
/*	This function takes a string as input and return there binary format.
	It might be noted the string is pre-processed and thus each character in that string has the ASCI value between 1 to 16. */
vector<bool> con(string text)
{
    vector<bool>ret;
    f(i,0,text.size())
    {
        bool temp[9];
        int num=text[i];
        f(j,0,4)
        {
            temp[j]=num%2;
            num/=2;
        }
        for(int i=3; i>-1; i--) ret.push_back(temp[i]);
    }
    return ret;
}

string hexaNum="0123456789ABCDEF";
/*This class is the class which stores and process the plaintext .*/
class plainText
{
public:
    string ptext="abcdefghijklmnop";
    bool pinBin[65];
    bool Left[33], Right[33];
    void process()
    {
        f(i,0,16)
        {
            if(ptext[i]>='0' && ptext[i]<='9') ptext[i]-='0';
            else if(ptext[i]>='a' && ptext[i]<='f') ptext[i]=ptext[i]-'a'+10;
            else if(ptext[i]>='A' && ptext[i]<='F') ptext[i]=ptext[i]-'A'+10;
        }
        vector<bool>pinh=con(ptext);
        int maptext[]= {58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
                        62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
                        57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
                        61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
                       };

        f(i,0,64) pinBin[i]=pinh[maptext[i]-1];
        f(i,0,32) Left[i]=pinBin[i];
        f(i,32,64) Right[i-32]=pinBin[i];
    }
};
/*This class is the class which stores and process the plaintext .*/
class key
{
public:
    string key="bddefhhjjllmnppb";
    bool kinBin[57];

    bool subkey[17][57];
    void process()
    {
        // f(i,0,16) key[i]=key[i]-'a';
        f(i,0,16)
        {
            if(key[i]>='0' && key[i]<='9') key[i]-='0';
            else if(key[i]>='a' && key[i]<='f') key[i]=key[i]-'a'+10;
            else if(key[i]>='A' && key[i]<='F') key[i]=key[i]-'A'+10;
        }
        vector<bool>kinh=con(key);
        int mapkey[]= {57,   49,    41,   33,    25,    17,    9,
                       1,   58,    50,   42,    34,    26,   18,
                       10,    2,    59,   51,    43,    35,   27,
                       19,   11,     3,   60,    52,    44,   36,
                       63,   55,    47,   39,    31,    23,   15,
                       7,   62,    54,   46,    38,    30,   22,
                       14,    6,    61,   53,    45,    37,   29,
                       21,   13,     5,   28,    20,    12,    4
                      };
        f(i,0,56) kinBin[i]=kinh[mapkey[i]-1];
        f(i,0,27) subkey[0][i]=kinBin[i+1];
        subkey[0][27]=kinBin[0];
        f(i,28,55) subkey[0][i]=kinBin[i+1];
        subkey[0][55]=kinBin[28];
        f(i,1,16)
        {
            if(i==1 || i==8 || i==15)
            {
                f(j,0,27)  subkey[i][j]=subkey[i-1][j+1];
                subkey[i][27]=subkey[i-1][0];
                f(j,28,55) subkey[i][j]=subkey[i-1][j+1];
                subkey[i][55]=subkey[i-1][28];
            }
            else
            {
                f(j,0,26)  subkey[i][j]=subkey[i-1][j+2];
                subkey[i][26]=subkey[i-1][0];
                subkey[i][27]=subkey[i-1][1];
                f(j,28,54) subkey[i][j]=subkey[i-1][j+2];
                subkey[i][54]=subkey[i-1][28];
                subkey[i][55]=subkey[i-1][29];
            }
        }
        int K[]= {14,    17,   11,    24,     1,    5,
                  3,    28,   15,     6,    21,   10,
                  23,    19,   12,     4,    26,    8,
                  16,     7,   27,    20,    13,    2,
                  41,    52,   31,    37,    47,   55,
                  30,    40,   51,    45,    33,   48,
                  44,    49,   39,    56,    34,   53,
                  46,    42,   50,    36,    29,   32
                 };
        f(i,0,16)
        {
            f(j,0,48)
            {
                kinBin[j]=subkey[i][K[j]-1];
            }
            f(j,0,48) subkey[i][j]=kinBin[j];
        }
    }
};
/*Previous two classes were made just to store and pre-process the plaintext and key respectively. Whereas, DES class is made to do what we are here for, the main encryption / decryption.*/
class DES
{
public:
    plainText textInstance;
    key keyInstance;
    string cipher;
    vector<string> cipherBuffer;
    bool cinBin[65];
    int Sbox[8][5][17]=
    {
        {   {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },

        {   {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },

        {   {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },

        {   {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },

        {   {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },

        {   {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },

        {   {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },

        {   {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
    /*It might seems odd there is only one for which is for encoding, that means there is no such function to decode data. It’s easy if one can encrypt because decryption in DES is just the inverse  process.  Here a parameter “isDecode” is passed as to define whether it is encryption of decryption.  If it’s ‘1’ it does the necessary “inverse” things. While when it’s ‘0’ such inversion is not needed. */
    void encode (int isDecode)
    {
        cipher.clear();
        bool newLeft[33], newRight[33];
        int E[]= {32,     1,    2,     3,     4,    5,
                  4,     5,    6,     7,     8,    9,
                  8,     9,   10,    11,    12,   13,
                  12,    13,   14,    15,    16,   17,
                  16,    17,   18,    19,    20,   21,
                  20,    21,   22,    23,    24,   25,
                  24,    25,   26,    27,    28,   29,
                  28,    29,   30,    31,    32,    1
                 };

        bool exKey[49];
        f(p,0,16)
        {
            int k;
            if(isDecode) k=15-p;
            else k=p;
            f(i,0,32) newLeft[i]=textInstance.Right[i];
            f(j,0,48) exKey[j]=keyInstance.subkey[k][j]^textInstance.Right[E[j]-1];
            //f(j,0,48) {cout<<exKey[j]; if(j%6==5) cout<<" ";}
            f(i,0,8)
            {
                int temp=Sbox[i][exKey[i*6]*2+exKey[i*6+5]][exKey[i*6+1]*8+exKey[i*6+2]*4+exKey[i*6+3]*2+exKey[i*6+4]];
                f(j,1,5)
                {
                    exKey[(i+1)*4-j]=temp%2;
                    temp/=2;
                }
            }
            int Pbox[]= {16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
                         2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4,  25
                        };

            f(i,0,32)
            {
                textInstance.Right[i]=newRight[i]=exKey[Pbox[i]-1]^textInstance.Left[i];
                textInstance.Left[i]=newLeft[i];
            }
            if(isDecode) k-=15;
        }
        int IP[]= {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                   38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                   36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                   34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25
                  };
        f(i,0,64)
        {
            if(IP[i]<33) cinBin[i]=textInstance.Right[IP[i]-1];
            else cinBin[i]=textInstance.Left[IP[i]-33];
        }
        f(i,0,16) cipher+=(cinBin[i*4]*8+cinBin[i*4+1]*4+cinBin[i*4+2]*2+cinBin[i*4+3]);
        if(isDecode) f(i,0,8) cipher[i]=cipher[i*2]*16+cipher[i*2+1];
    }

};

int main()
{
    DES test;  		//That is DES instance
    string mainText, mainKey;
    int command;
    while(1)
    {
        cout<<"\n\n\n\t\t\t\tThis program is able to encrypt \n\t\t\t\tor decrypt data using \n\t\t\t\tData Encryption Standard (DES)\n\n";
        cout<<"\t\t\t\t\t\t-Prepared By Mohammad Sheikh Ghazanfar\n\n\n";
        cout<<"\t\t\t\t\t1. Encrypt\n"<<"\t\t\t\t\t2. Decrypt\n"<<"\t\t\t\t\t3. Exit\n";
        cin>>command;
        cin.ignore();
        if(command==1)
        {
            cout<<"Text : ";
            getline(cin, mainText);
            cout<<"Key (in Hexadecimal) : ";
            getline(cin, mainKey);
            while(mainText.size()%8 !=0) mainText+='0';
            /*Being sure if the number of character in the plain text is devisible by 8 or not. */
            if(mainKey.size() < 2*mainText.size())
            {
                string _key=mainKey;
                while(mainKey.size() < 2*mainText.size()) mainKey+=_key;
            }
            /*Being Sure if key size is appropriate*/
            cout<<"Cipher Text : ";
            f(i,0,mainText.size())
            {
                test.textInstance.ptext.clear();
                test.keyInstance.key.clear();
                f(j,i,i+8)
                {
                    int t=(int)mainText[j]%16;
                    test.textInstance.ptext+=hexaNum[(int)(mainText[j]/16)];
                    test.textInstance.ptext+=hexaNum[t];
                }
                test.keyInstance.key=mainKey.substr(i*2,16);
                test.textInstance.process();
                test.keyInstance.process();
                test.encode(0);
                i+=7;
                f(j,0,test.cipher.size()) cout<<hexaNum[test.cipher[j]];
            }
            cout<<endl;
        }
        else if(command==2)
        {
            cout<<"Cipher Text (in Hexadecimal) : ";
            getline(cin, mainText);
            cout<<"Key (in Hexadecimal) : ";
            getline(cin, mainKey);
            while(mainText.size()%16 !=0) mainText+='0';
            if(mainKey.size() < mainText.size())
            {
                string _key=mainKey;
                while(mainKey.size() < mainText.size()) mainKey+=_key;
            }
            cout<<"Plain Text : ";
            f(i,0,mainText.size())
            {
                test.textInstance.ptext.clear();
                test.keyInstance.key.clear();
                f(j,i,i+16)
                {
                    test.textInstance.ptext+=mainText[j];
                }
                test.keyInstance.key=mainKey.substr(i,16);
                test.textInstance.process();
                test.keyInstance.process();
                test.encode(1);
                i+=15;
                f(j,0,test.cipher.size()/2) cout<<hex<<(char)test.cipher[j];
            }
            cout<<endl;
        }
        else if(command==3) break;
        else
        {
            cout<<"Press press any number 1 to 3"<<endl;
        }
    }
    return 0;
}
