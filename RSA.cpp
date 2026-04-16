#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <tuple>
#include <utility>
#include <cctype>
#include <stdexcept>

using ll = long long;

// Safe modular multiplication (portable - works on x86 and x64)
ll modMul(ll a, ll b, ll mod) {
    if (mod == 0) return 0;
    ll res = 0;
    a %= mod;
    if (a < 0) a += mod;
    b %= mod;
    if (b < 0) b += mod;
    while (b > 0) {
        if (b & 1) {
            res = (res + a) % mod;
        }
        a = (a * 2) % mod;
        b >>= 1;
    }
    return res;
}

// Modular exponentiation (core of RSA)
ll modPow(ll base, ll exp, ll mod) {
    if (mod == 1) return 0;
    ll result = 1;
    base %= mod;
    if (base < 0) base += mod;
    while (exp > 0) {
        if (exp & 1) {
            result = modMul(result, base, mod);
        }
        base = modMul(base, base, mod);
        exp >>= 1;
    }
    return result;
}

// Euclidean algorithm (GCD)
ll gcd(ll a, ll b) {
    while (b != 0) {
        ll t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Extended Euclidean algorithm (returns gcd, x, y such that a*x + b*y = gcd)
std::tuple<ll, ll, ll> extendedGcd(ll a, ll b) {
    if (b == 0) {
        return std::make_tuple(a, 1LL, 0LL);
    }
    auto rec = extendedGcd(b, a % b);
    ll g = std::get<0>(rec);
    ll x1 = std::get<1>(rec);
    ll y1 = std::get<2>(rec);
    ll x = y1;
    ll y = x1 - (a / b) * y1;
    return std::make_tuple(g, x, y);
}

// Modular multiplicative inverse
ll modInverse(ll a, ll m) {
    auto rec = extendedGcd(a, m);
    ll g = std::get<0>(rec);
    if (g != 1) {
        throw std::runtime_error("Inverse does not exist (e and phi are not coprime)");
    }
    ll x = std::get<1>(rec);
    return (x % m + m) % m;
}

// Choose public exponent e (smallest e >= 2 that is coprime to phi)
ll chooseE(ll phi) {
    for (ll e = 2; e < phi; ++e) {
        if (gcd(e, phi) == 1) {
            return e;
        }
    }
    return -1; // Should never happen for valid primes
}

// Check if number is prime
bool isPrime(ll num) {
    if (num <= 1) return false;
    if (num == 2 || num == 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;
    for (ll i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }
    return true;
}

// Factor n into two primes p and q (mathematical attack)
std::pair<ll, ll> factorN(ll n) {
    if (n < 2) return { 1, 1 };
    if (n % 2 == 0) return { 2, n / 2 };
    for (ll i = 3; i * i <= n; i += 2) {
        if (n % i == 0) {
            return { i, n / i };
        }
    }
    return { n, 1 }; // n is prime
}

// Encrypt plaintext (each char as ASCII/Unicode value)
std::vector<ll> encrypt(const std::string& text, ll e, ll n) {
    std::vector<ll> cipher;
    for (char ch : text) {
        ll m = static_cast<unsigned char>(ch); // 0-255
        if (m >= n) {
            throw std::runtime_error("Character value >= n. Use larger primes p and q.");
        }
        ll c = modPow(m, e, n);
        cipher.push_back(c);
    }
    return cipher;
}

// Decrypt ciphertext
std::string decrypt(const std::vector<ll>& cipher, ll d, ll n) {
    std::string text;
    for (ll c : cipher) {
        ll m = modPow(c, d, n);
        text += static_cast<char>(m);
    }
    return text;
}

int main() {
    std::cout << "=== RSA Encryption/Decryption System (Level B - No Library) ===\n";
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

            if (!isPrime(p) || !isPrime(q) || p == q) {
                std::cout << "Error: p and q must be distinct primes!\n";
                continue;
            }

            ll n = p * q;
            ll phi = (p - 1) * (q - 1);
            ll e = chooseE(phi);

            if (e == -1) {
                std::cout << "Error: Could not find public exponent e.\n";
                continue;
            }

            if (n <= 255) {
                std::cout << "Warning: n is small (<=255). Some characters may not encrypt correctly.\n";
            }

            std::cout << "RSA parameters calculated:\n";
            std::cout << "  n = " << n << "\n";
            std::cout << "  Φ = " << phi << "\n";
            std::cout << "  Public key (n, e) = (" << n << ", " << e << ")\n";

            std::string text;
            std::cout << "\nEnter plaintext (can contain spaces): ";
            std::cin.ignore(); // Clear newline
            std::getline(std::cin, text);

            try {
                auto cipher = encrypt(text, e, n);

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
            std::cout << "  Public key (n, e) = (" << n << ", " << e << ")\n";
            std::cout << "  Ciphertext size: " << cipher.size() << " numbers\n";

            // Mathematical attack: factor n to recover p and q
            std::pair<ll, ll> pq = factorN(n);
            ll p = pq.first;
            ll q = pq.second;

            if (p * q != n || p <= 1 || q <= 1 || !isPrime(p) || !isPrime(q)) {
                std::cout << "Factoring attack failed (could not recover two primes).\n";
                std::cout << "Use smaller primes in encryption for successful demo.\n";
                continue;
            }

            std::cout << "Mathematical attack successful!\n";
            std::cout << "  Recovered primes: p = " << p << ", q = " << q << "\n";

            ll phi = (p - 1) * (q - 1);
            ll d = modInverse(e, phi);

            std::cout << "  Φ = " << phi << "\n";
            std::cout << "  Private key d = " << d << "\n";

            try {
                std::string decryptedText = decrypt(cipher, d, n);
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