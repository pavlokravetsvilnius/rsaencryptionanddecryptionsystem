#include "RSA.h"
#include <stdexcept>

std::vector<ll> RSA::encrypt(const std::string& text, ll e, ll n) {
    std::vector<ll> cipher;
    for (char ch : text) {
        ll m = static_cast<unsigned char>(ch); // 0-255
        if (m >= n) {
            throw std::runtime_error("Character value >= n. Use larger primes p and q.");
        }
        ll c = RSAMath::modPow(m, e, n);
        cipher.push_back(c);
    }
    return cipher;
}

std::string RSA::decrypt(const std::vector<ll>& cipher, ll d, ll n) {
    std::string text;
    for (ll c : cipher) {
        ll m = RSAMath::modPow(c, d, n);
        text += static_cast<char>(m);
    }
    return text;
}