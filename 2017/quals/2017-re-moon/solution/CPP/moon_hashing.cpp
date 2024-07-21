#include <iostream>
#include <math.h>
#include <iomanip>
#include "Vec3.h"
#include "Mat3.h"

static const unsigned int passwordSize = 32;
static const unsigned int stateSize = 64;
static const unsigned int hashSize = 64;
static unsigned int password[passwordSize];
static unsigned int state[stateSize];
static unsigned int hash[hashSize];


Vec3 calc(unsigned int p){
	double PI = 3.14159265358979323846;
	double r= p * PI / double(180.0);
	double c=cos(r);
	double s=sin(r);
	Mat3 m=Mat3(c,-s,0.0,s,c,0.0,0.0,0.0,1.0);
	Vec3 pt (1024.0,0.0,0.0);
	Vec3 res=pt*m;
	res+=Vec3(2048.0,2048.0,0.0);
	std::cout << "p=" << p << " x=" << res[0] << " y=" << res[1] << std::endl;
	return res;
}

unsigned int extend(unsigned int e){
	std::cout << "extend e = " << e << std::endl;
	unsigned int i;
	unsigned int r=e^0x5f208c26;
	for (i=15;i<31;i+=3){
		unsigned int f=e<<i;
		r^=f;
	}
	std::cout << "extend r = " << r << std::endl;
	return r;
}

unsigned int hash_alpha(unsigned int p){
	Vec3 res=calc(p);
	std::cout << "alpha vec = (" << res[0] << "," << res[1] << ")" << std::endl;
	return extend(unsigned int(res[0]));
}

unsigned int hash_beta(unsigned int p){
	Vec3 res=calc(p);
	return extend(unsigned int(res[1]));
}

static void ShaderMain(unsigned int globalIdX, unsigned int globalIdY)
{
	unsigned int idx=globalIdX+globalIdY*8;
	std::cout << "idx = " << idx << std::endl;
	unsigned int finalValue;
	if (state[idx]!=1){
		return;
	}if ((idx&1)==0){
		finalValue=hash_alpha(password[idx/2]);
	}else{
		finalValue=hash_beta(password[idx/2]);
	}
	std::cout << "final value after alpha = " << finalValue << std::endl;
	unsigned int i;
	for (i=0;i<32;i+=6){
		finalValue^=idx<<i;
	}
	std::cout << "final value after idx xoring = " << finalValue << std::endl;
	
	unsigned int h=0x5a;
	for (i=0;i<32;i++){
		unsigned int p=password[i];
		unsigned int r=(i*3)&7;
		p=(p<<r)|(p>>(8-r));
		p&=0xff;h^=p;
	}
	
	std::cout << "h = " << h << std::endl;
	finalValue^=(h|(h<<8)|(h<<16)|(h<<24));
	
	std::cout << "hash[" << idx << "] = " << finalValue << std::endl;
	
	hash[idx]=finalValue;
	
	state[idx]=2;
}


int main()
{	
	std::string inputValues = "12345678901234567890123456789012";
	for(int i = 0; i < passwordSize; ++i)
	{
		password[i] = inputValues[i];
	}
	for(int i = 0; i < stateSize; ++i)
	{
		state[i] = 1;
	}
	for(int i = 0; i < hashSize; ++i)
	{
		hash[i] = 0;
	}
	
	for(int y = 0; y < 8; ++y)
	{
		for(int x = 0; x < 8; ++x)
		{
			ShaderMain(x, y);
		}
	}
	for(int i = 0; i < hashSize; ++i)
	{
		std::cout << std::setfill('0') << std::setw(8) << std::hex << hash[i];
	}
}