#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
using namespace std;
static unsigned char gm(unsigned char a,unsigned char b){unsigned char z=0;while(b){if(b&1)z^=a;bool hi=a&0x80;a<<=1;if(hi)a^=0x1b;b>>=1;}return z;}
int main(int argc,char**argv){if(argc!=5){cerr<<"usage: solver maps coeff n out\n";return 2;}
 ifstream mf(argv[1],ios::binary),cf(argv[2],ios::binary);int n=stoi(argv[3]);ofstream out(argv[4],ios::binary);
 vector<unsigned char> maps(1024),coef(4*n);mf.read((char*)maps.data(),maps.size());cf.read((char*)coef.data(),coef.size());
 vector<uint32_t> vals; vals.reserve(n==1?2000:100000);
 for(int e0=1;e0<256;e0++) for(int e1=(n==1?0:1);e1<(n==1?1:256);e1++){
  unsigned char d[4];for(int r=0;r<4;r++) d[r]=0;
  for(int r=0;r<4;r++){d[r]=gm(coef[r*n],(unsigned char)e0); if(n==2)d[r]^=gm(coef[r*n+1],(unsigned char)e1);}
  vector<unsigned char> ks[4];bool ok=true;
  for(int r=0;r<4;r++){for(int k=0;k<256;k++)if(maps[r*256+k]==d[r])ks[r].push_back((unsigned char)k);if(ks[r].empty()){ok=false;break;}}
  if(ok)for(auto a:ks[0])for(auto b:ks[1])for(auto c:ks[2])for(auto d4:ks[3]) vals.push_back((uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|d4);
 }
 sort(vals.begin(),vals.end());vals.erase(unique(vals.begin(),vals.end()),vals.end());
 out.write((char*)vals.data(),vals.size()*sizeof(uint32_t));
}
