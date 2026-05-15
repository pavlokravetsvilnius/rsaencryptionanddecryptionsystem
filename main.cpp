#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <cctype>
#include "RSA.h"
#include "RSAMath.h"

namespace {
    void clearInputBuffer() {
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    void printHeader() {
        std::cout << "=== RSA Encryption/Decryption System (Improved OOP) ===\n";
        std::cout << "Educational demo - Small primes only for factoring attack\n\n";
    }

    bool generateKeys(ll& p, ll& q, ll& n, ll& phi, ll& e) {
        std::cout << "Enter two distinct prime numbers p and q: ";
        std::cin >> p >> q;
        clearInputBuffer();

        if (!RSAMath::isPrime(p) || !RSAMath::isPrime(q) || p == q) {
            std::cout << "Error: Both numbers must be distinct primes.\n";
            return false;
        }

        n = p * q;
        phi = (p - 1) * (q - 1);
        e = RSAMath::chooseE(phi);

        if (e == -1) {
            std::cout << "Error: Could not find public exponent e.\n";
            return false;
        }

        if (n <= 255) {
            std::cout << "Warning: n is small (<=255). Some characters may fail to encrypt.\n";
        }

        std::cout << "\nKeys generated:\n";
        std::cout << "  p = " << p << ", q = " << q << "\n";
        std::cout << "  n = " << n << "\n";
        std::cout << "  Φ(n) = " << phi << "\n";
        std::cout << "  Public key (n, e) = (" << n << ", " << e << ")\n";
        return true;
    }
}

int main() {
    printHeader();

    while (true) {
        std::cout << "\nMenu:\n";
        std::cout << "1. Generate keys & Encrypt\n";
        std::cout << "2. Decrypt from file (with factoring attack)\n";
        std::cout << "3. Exit\n";
        std::cout << "Choice: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            clearInputBuffer();
            continue;
        }
        clearInputBuffer();

        if (choice == 1) {
            // === ENCRYPTION ===
            ll p = 0, q = 0, n = 0, phi = 0, e = 0;
            if (!generateKeys(p, q, n, phi, e)) continue;

            std::string text;
            std::cout << "\nEnter plaintext: ";
            std::getline(std::cin, text);

            if (text.empty()) {
                std::cout << "Empty text, nothing to encrypt.\n";
                continue;
            }

            try {
                auto cipher = RSA::encrypt(text, e, n);
                std::cout << "\nCiphertext: ";
                for (ll c : cipher) std::cout << c << ' ';
                std::cout << "\n\n";

                std::cout << "Save to file? (y/n): ";
                char save;
                std::cin >> save;
                clearInputBuffer();

                if (std::tolower(save) == 'y') {
                    std::string filename;
                    std::cout << "Filename: ";
                    std::getline(std::cin, filename);
                    if (filename.empty()) filename = "encrypted.txt";

                    std::ofstream out(filename);
                    if (!out) {
                        std::cout << "Failed to create file!\n";
                        continue;
                    }

                    out << n << ' ' << e << '\n';
                    for (ll c : cipher) out << c << ' ';
                    out << '\n';

                    std::cout << "Saved to " << filename << "\n";
                }
            }
            catch (const std::exception& ex) {
                std::cout << "Encryption error: " << ex.what() << '\n';
            }
        }
        else if (choice == 2) {
            // === DECRYPTION WITH ATTACK ===
            std::string filename;
            std::cout << "Enter filename: ";
            std::getline(std::cin, filename);
            if (filename.empty()) filename = "encrypted.txt";

            std::ifstream in(filename);
            if (!in) {
                std::cout << "Cannot open file: " << filename << '\n';
                continue;
            }

            ll n = 0, e = 0;
            in >> n >> e;

            std::vector<ll> cipher;
            ll val;
            while (in >> val) {
                cipher.push_back(val);
            }

            if (cipher.empty()) {
                std::cout << "No ciphertext found in file.\n";
                continue;
            }

            std::cout << "\nLoaded: n=" << n << ", e=" << e
                << ", " << cipher.size() << " blocks\n";

            // Mathematical attack - Fixed for C++14
            std::pair<ll, ll> pq = RSAMath::factorN(n);
            ll p = pq.first;
            ll q = pq.second;

            if (p * q != n || !RSAMath::isPrime(p) || !RSAMath::isPrime(q)) {
                std::cout << "Factoring failed. Use smaller primes (e.g. < 10^6).\n";
                continue;
            }

            ll phi = (p - 1) * (q - 1);
            ll d = RSAMath::modInverse(e, phi);

            std::cout << "Attack successful!\n";
            std::cout << "  p = " << p << ", q = " << q << "\n";
            std::cout << "  d = " << d << "\n";

            try {
                std::string decrypted = RSA::decrypt(cipher, d, n);
                std::cout << "\nDecrypted: " << decrypted << '\n';
            }
            catch (const std::exception& ex) {
                std::cout << "Decryption error: " << ex.what() << '\n';
            }
        }
        else if (choice == 3) {
            std::cout << "Goodbye!\n";
            break;
        }
        else {
            std::cout << "Invalid option.\n";
        }
    }
    return 0;
}