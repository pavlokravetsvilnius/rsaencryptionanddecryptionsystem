#include "RSAMath.h"
#include <stdexcept>

ll RSAMath::modMul(ll a, ll b, ll mod) {
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

ll RSAMath::modPow(ll base, ll exp, ll mod) {
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

ll RSAMath::gcd(ll a, ll b) {
    while (b != 0) {
        ll t = b;
        b = a % b;
        a = t;
    }
    return a;
}

std::tuple<ll, ll, ll> RSAMath::extendedGcd(ll a, ll b) {
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

ll RSAMath::modInverse(ll a, ll m) {
    auto rec = extendedGcd(a, m);
    ll g = std::get<0>(rec);
    if (g != 1) {
        throw std::runtime_error("Inverse does not exist (e and phi are not coprime)");
    }
    ll x = std::get<1>(rec);
    return (x % m + m) % m;
}

ll RSAMath::chooseE(ll phi) {
    for (ll e = 2; e < phi; ++e) {
        if (gcd(e, phi) == 1) {
            return e;
        }
    }
    return -1;
}

bool RSAMath::isPrime(ll num) {
    if (num <= 1) return false;
    if (num == 2 || num == 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;
    for (ll i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }
    return true;
}

std::pair<ll, ll> RSAMath::factorN(ll n) {
    if (n < 2) return { 1, 1 };
    if (n % 2 == 0) return { 2, n / 2 };
    for (ll i = 3; i * i <= n; i += 2) {
        if (n % i == 0) {
            return { i, n / i };
        }
    }
    return { n, 1 };
}