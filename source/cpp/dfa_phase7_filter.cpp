// Phase VII AES-DFA candidate filter. No external crypto/algorithm libraries.
// Input: packed uint32 candidates (little-endian), 1024-byte dmap, 9-byte invA.
// Output: packed uint32 survivors (little-endian).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <array>
#include <iostream>

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t out = 0;
    while (b) {
        if (b & 1) out ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: dfa_phase7_filter input_candidates.bin output_candidates.bin maps_and_inverse.bin\n";
        return 2;
    }
    FILE* fi = std::fopen(argv[1], "rb");
    FILE* fo = std::fopen(argv[2], "wb");
    FILE* fm = std::fopen(argv[3], "rb");
    if (!fi || !fo || !fm) { std::cerr << "file open failed\n"; return 3; }
    std::array<std::array<uint8_t,256>,4> d{};
    std::array<std::array<uint8_t,3>,3> inv{};
    std::array<uint8_t,3> row4{};
    if (std::fread(d.data(), 1, 1024, fm) != 1024 || std::fread(inv.data(),1,9,fm)!=9 || std::fread(row4.data(),1,3,fm)!=3) {
        std::cerr << "bad map/inverse file\n"; return 4;
    }
    std::array<uint8_t,256*256> gf{};
    for (int a=0;a<256;++a) for (int b=0;b<256;++b) gf[a*256+b]=gf_mul(a,b);
    uint64_t seen=0, kept=0;
    std::array<uint32_t,1<<16> outbuf{}; size_t used=0;
    uint32_t packed;
    while (std::fread(&packed,sizeof(packed),1,fi)==1) {
        ++seen;
        uint8_t k0=(packed>>24)&255, k1=(packed>>16)&255, k2=(packed>>8)&255, k3=packed&255;
        uint8_t ds[4]={d[0][k0],d[1][k1],d[2][k2],d[3][k3]};
        uint8_t eps[3];
        for (int j=0;j<3;++j) {
            eps[j]=gf[inv[j][0]*256+ds[0]] ^ gf[inv[j][1]*256+ds[1]] ^ gf[inv[j][2]*256+ds[2]];
        }
        if (eps[0]==0 || eps[1]==0 || eps[2]==0) continue;
        uint8_t expected4 = gf[row4[0]*256+eps[0]] ^ gf[row4[1]*256+eps[1]] ^ gf[row4[2]*256+eps[2]];
        if (expected4 != ds[3]) continue;
        if (used==outbuf.size()) { std::fwrite(outbuf.data(),sizeof(uint32_t),used,fo); used=0; }
        outbuf[used++]=packed; ++kept;
    }
    if (used) std::fwrite(outbuf.data(),sizeof(uint32_t),used,fo);
    std::fclose(fi); std::fclose(fo); std::fclose(fm);
    std::cout << "seen=" << seen << " kept=" << kept << "\n";
    return 0;
}
