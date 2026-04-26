#pragma once
#include <tuple>
#include <utility>

using ll = long long;

class RSAMath {
public:
    static ll modMul(ll a, ll b, ll mod);
    static ll modPow(ll base, ll exp, ll mod);
    static ll gcd(ll a, ll b);
    static std::tuple<ll, ll, ll> extendedGcd(ll a, ll b);
    static ll modInverse(ll a, ll m);
    static ll chooseE(ll phi);
    static bool isPrime(ll num);
    static std::pair<ll, ll> factorN(ll n);
};