// C++ candidate generator for three-byte AES DFA; all GF arithmetic implemented here.
#include <cstdint>
#include <cstdio>
#include <array>
#include <vector>
#include <iostream>
static uint8_t mul(uint8_t a,uint8_t b){uint8_t o=0;while(b){if(b&1)o^=a;bool h=a&128;a<<=1;if(h)a^=0x1b;b>>=1;}return o;}
int main(int argc,char**argv){if(argc!=4){std::cerr<<"usage: gen maps.bin coefficients.bin out.bin\n";return 2;}
 FILE*fm=fopen(argv[1],"rb"),*fc=fopen(argv[2],"rb"),*fo=fopen(argv[3],"wb");if(!fm||!fc||!fo)return 3;
 std::array<std::array<uint8_t,256>,4>d{}; if(fread(d.data(),1,1024,fm)!=1024)return 4;
 // coefficients: 4 rows x 3 faulted-row columns, row-major; then inverse of coefficient at output row 3.
 uint8_t coeff[12],inv=0;if(fread(coeff,1,12,fc)!=12||fread(&inv,1,1,fc)!=1)return 5;
 uint8_t gf[256][256];for(int a=0;a<256;a++)for(int b=0;b<256;b++)gf[a][b]=mul(a,b);
 std::array<std::array<uint8_t,256>,4> keys{};std::array<std::array<uint16_t,256>,4> counts{};
 // d[row][key] -> list of keys for each differential value
 std::array<std::array<std::array<uint8_t,256>,256>,4> rev{};
 for(int r=0;r<4;r++)for(int k=0;k<256;k++){uint8_t v=d[r][k];rev[r][v][counts[r][v]++]=k;}
 uint64_t generated=0;std::array<uint32_t,1<<16> buf{};size_t used=0;
 for(int ea=1;ea<256;ea++){
  uint8_t a0=gf[coeff[0]][ea],a1=gf[coeff[3]][ea],a2=gf[coeff[6]][ea],a3=gf[coeff[9]][ea];
  for(int eb=1;eb<256;eb++){
   uint8_t b0=gf[coeff[1]][eb],b1=gf[coeff[4]][eb],b2=gf[coeff[7]][eb],b3=gf[coeff[10]][eb];
   uint8_t v0=a0^b0,v1=a1^b1,v2=a2^b2,v3=a3^b3;
   for(int k3=0;k3<256;k3++){
    uint8_t ec=gf[inv][d[3][k3]^v3];if(!ec)continue;
    uint8_t t0=v0^gf[coeff[2]][ec],t1=v1^gf[coeff[5]][ec],t2=v2^gf[coeff[8]][ec],t3=v3^gf[coeff[11]][ec];
    if(d[3][k3]!=t3)continue;
    uint16_t n0=counts[0][t0],n1=counts[1][t1],n2=counts[2][t2];if(!n0||!n1||!n2)continue;
    for(int i=0;i<n0;i++)for(int j=0;j<n1;j++)for(int k=0;k<n2;k++){
     uint32_t x=(uint32_t(rev[0][t0][i])<<24)|(uint32_t(rev[1][t1][j])<<16)|(uint32_t(rev[2][t2][k])<<8)|uint32_t(k3);
     buf[used++]=x;++generated;if(used==buf.size()){fwrite(buf.data(),4,used,fo);used=0;}
    }
   }
  }
 }
 if(used)fwrite(buf.data(),4,used,fo);fclose(fm);fclose(fc);fclose(fo);std::cout<<"generated="<<generated<<"\n";
}
