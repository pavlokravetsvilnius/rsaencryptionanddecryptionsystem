#include "RSA.h"
#include <stdexcept>

std::vector<ll> RSA::encrypt(const std::string& text, ll e, ll n) {
    std::vector<ll> cipher;
    cipher.reserve(text.size());

    for (unsigned char ch : text) {                 // unsigned char → 0-255
        if (ch >= n) {
            throw std::runtime_error("Character value >= n. Use larger primes.");
        }
        cipher.push_back(RSAMath::modPow(ch, e, n));
    }
    return cipher;
}

std::string RSA::decrypt(const std::vector<ll>& cipher, ll d, ll n) {
    std::string text;
    text.reserve(cipher.size());

    for (ll c : cipher) {
        ll m = RSAMath::modPow(c, d, n);
        if (m < 0 || m > 255) {
            throw std::runtime_error("Decrypted value out of char range");
        }
        text += static_cast<char>(m);
    }
    return text;
}