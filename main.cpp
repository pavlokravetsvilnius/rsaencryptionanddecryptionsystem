#include <iostream>
#include <fstream>
#include <string>
#include <cctype>
#include <vector>
#include "RSAMath.h"
#include "RSA.h"

int main() {
    std::cout << "=== RSA Encryption/Decryption System (Level B - OOP Version) ===\n";
    std::cout << "Fixed version - compiles with default Visual Studio settings\n";
    std::cout << "Uses files for storage. Full RSA workflow + mathematical attack.\n\n";

    while (true) {
        std::cout << "\nMenu:\n";
        std::cout << "1. Encrypt plaintext (input p, q, text -> save to file)\n";
        std::cout << "2. Decrypt from file (read cipher + public key -> factor n -> decrypt)\n";
        std::cout << "3. Exit\n";
        std::cout << "Choose option (1-3): ";

        int choice;
        std::cin >> choice;

        if (choice == 1) {
            // === ENCRYPTION ===
            ll p, q;
            std::cout << "\nEnter two distinct prime numbers p and q: ";
            std::cin >> p >> q;

            if (!RSAMath::isPrime(p) || !RSAMath::isPrime(q)  || p == q) {
                std::cout << "Error: p and q must be distinct primes!\n";
                continue;
            }

            ll n = p * q;
            ll phi = (p - 1) * (q - 1);
            ll e = RSAMath::chooseE(phi);

            if (e == -1) {
                std::cout << "Error: Could not find public exponent e.\n";
                continue;
            }

            if (n <= 255) {
                std::cout << "Warning: n is small (<=255). Some characters may not encrypt correctly.\n";
            }

            std::cout << "RSA parameters calculated:\n";
            std::cout << " n = " << n << "\n";
            std::cout << " Φ = " << phi << "\n";
            std::cout << " Public key (n, e) = (" << n << ", " << e << ")\n";

            std::string text;
            std::cout << "\nEnter plaintext (can contain spaces): ";
            std::cin.ignore(); // Clear newline
            std::getline(std::cin, text);

            try {
                auto cipher = RSA::encrypt(text, e, n);
                std::cout << "\nEncrypted text (numbers): ";
                for (ll c : cipher) {
                    std::cout << c << " ";
                }
                std::cout << "\n";

                // Save to file
                std::cout << "\nSave encrypted text + public key to file? (y/n): ";
                char saveChoice;
                std::cin >> saveChoice;
                if (std::tolower(saveChoice) == 'y') {
                    std::string filename;
                    std::cout << "Enter filename (e.g. encrypted.txt): ";
                    std::cin >> filename;

                    std::ofstream outFile(filename);
                    if (!outFile) {
                        std::cout << "Error: Could not create file!\n";
                        continue;
                    }
                    outFile << n << " " << e << "\n";
                    for (ll c : cipher) {
                        outFile << c << " ";
                    }
                    outFile << "\n";
                    outFile.close();

                    std::cout << "Successfully saved to " << filename << "\n";
                    std::cout << "File format: first line = n e, second line = ciphertext numbers\n";
                }
            }
            catch (const std::exception& ex) {
                std::cout << "Encryption error: " << ex.what() << "\n";
            }
        }
        else if (choice == 2) {
            // === DECRYPTION (with mathematical attack on n) ===
            std::string filename;
            std::cout << "\nEnter filename to decrypt (e.g. encrypted.txt): ";
            std::cin >> filename;

            std::ifstream inFile(filename);
            if (!inFile) {
                std::cout << "Error: File not found or cannot be opened!\n";
                continue;
            }

            ll n, e;
            inFile >> n >> e;

            std::vector<ll> cipher;
            ll val;
            while (inFile >> val) {
                cipher.push_back(val);
            }
            inFile.close();

            if (cipher.empty()) {
                std::cout << "Error: No ciphertext data in file!\n";
                continue;
            }

            std::cout << "\nLoaded from file:\n";
            std::cout << " Public key (n, e) = (" << n << ", " << e << ")\n";
            std::cout << " Ciphertext size: " << cipher.size() << " numbers\n";

            // Mathematical attack: factor n to recover p and q
            std::pair<ll, ll> pq = RSAMath::factorN(n);
            ll p = pq.first;
            ll q = pq.second;

            if (p * q != n || p <= 1 || q <= 1 || !RSAMath::isPrime(p) || !RSAMath::isPrime(q)) {
                std::cout << "Factoring attack failed (could not recover two primes).\n";
                std::cout << "Use smaller primes in encryption for successful demo.\n";
                continue;
            }

            std::cout << "Mathematical attack successful!\n";
            std::cout << " Recovered primes: p = " << p << ", q = " << q << "\n";

            ll phi = (p - 1) * (q - 1);
            ll d = RSAMath::modInverse(e, phi);

            std::cout << " Φ = " << phi << "\n";
            std::cout << " Private key d = " << d << "\n";

            try {
                std::string decryptedText = RSA::decrypt(cipher, d, n);
                std::cout << "\nDecrypted text: " << decryptedText << "\n";
            }
            catch (const std::exception& ex) {
                std::cout << "Decryption error: " << ex.what() << "\n";
            }
        }
        else if (choice == 3) {
            std::cout << "\nExiting RSA system. Goodbye!\n";
            break;
        }
        else {
            std::cout << "Invalid option. Try again.\n";
        }
    }
    return 0;
}