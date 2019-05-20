// g++ -DNDEBUG hashchain.cpp -lcryptopp -lpthread -O3
// ./a.out | tee out.txt
#include <iostream>
#include <iomanip>
#include <sstream>
#include <climits>
#include <string>
#include <ctime>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

std::string intTohex(const unsigned long int n) {
    std::ostringstream ostream;
    ostream << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << n;
    return ostream.str();
}

std::string sha256(std::string msg, bool isHex = false) {
    SHA256 hash;
    std::ostringstream ostream;
    HexEncoder encoder(new FileSink(ostream));
    std::string digest;

    if (isHex) {
        std::string decoded;
        StringSource ss(msg, true, new HexDecoder(new StringSink(decoded)));
        StringSource(decoded, true, new HashFilter(hash, new StringSink(digest)));
    }
    else
        StringSource(msg, true, new HashFilter(hash, new StringSink(digest)));

    StringSource(digest, true, new Redirector(encoder));

    return ostream.str();
}

void homework() {

    std::cout << sha256("Bitcoin is a cryptocurrency, a form of electronic cash.") << std::endl;
    unsigned int nLeading0s = 0;
    unsigned long int nTries = 0;
    std::string oldHash = sha256("Bitcoin");

    while (nLeading0s <= 64) {
        std::string nonce = intTohex(nTries);
        std::string newHash = sha256(oldHash + nonce, true);
        if (newHash.find(std::string(nLeading0s, '0')) == 0) {
            std::cout << nLeading0s << std::endl
                << oldHash << std::endl
                << nonce << std::endl
                << newHash << std::endl;
            oldHash = newHash;
            nLeading0s++;
            nTries = 0;
        }
        else
            nTries++;

        if (nTries == ULONG_MAX) {
            std::cerr << "Overflow" << std::endl;
            break;
        }
    }
}

void onsitetest() {

    time_t start;

	start = time(NULL);
	std::string oldHash = sha256("Homework 5");
	unsigned int nLeading0s = 0;
	unsigned long int nTries = 0;

	while (difftime(time(NULL), start) < 60 * 10) {
		std::string nonce = intTohex(nTries);
		std::string newHash = sha256(oldHash + nonce, true);
		if (newHash.find(std::string(nLeading0s, '1')) == 0) {
			std::cout << nLeading0s << std::endl
					  << oldHash << std::endl
					  << nonce << std::endl
					  << newHash << std::endl;
			oldHash = newHash;
			nLeading0s++;
			nTries = 0;
		}
		else
			nTries++;

		if (nTries == ULONG_MAX) {
			std::cerr << "Overflow" << std::endl;
			break;
		}

	}
}

int main() {

    homework();

    // onsitetest();

    return 0;
}