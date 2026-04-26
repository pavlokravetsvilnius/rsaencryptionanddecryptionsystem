#pragma once
#include <vector>
#include <string>
#include "RSAMath.h"

class RSA {
public:
    static std::vector<ll> encrypt(const std::string& text, ll e, ll n);
    static std::string decrypt(const std::vector<ll>& cipher, ll d, ll n);
};