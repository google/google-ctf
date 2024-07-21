#include <iostream>
#include <math.h>
#include <sstream>
#include <iomanip>
#include "Vec3.h"
#include "Mat3.h"

static const unsigned int passwordSize = 32;
static const unsigned int hashSize = 64;
static unsigned int password[passwordSize];
static unsigned int hash[hashSize];

static unsigned int reverse_calc(Vec3 res)
{
	std::cout << "res =(x = " << res[0] << ", y = " << res[1] << ")" << std::endl;
	double PI = 3.14159265358979323846;
	res +=Vec3(-2048.0,-2048.0,0.0);
	std::cout << "res after constant =(x = " << res[0] << ", y = " << res[1] << ")" << std::endl;
	float adj = res[0]/1024.0;
	float opo = res[1]/1024.0;
	
	float cosAng = acos(adj);
	float sinAng = abs(asin(opo));
	if( abs(cosAng - sinAng) > 0.01 )
	{
		std::cout << "not this one" << std::endl;
	}
	
	
	
	float tan_angle = abs(atan2(res[1],res[0]));
	unsigned int p = tan_angle * (180.0/PI);
	std::cout << "p = " << p << std::endl;
	return p;
}

static unsigned int reverse_extend(unsigned int r)
{
	std::cout << "r = " << r << std::endl;
	unsigned int e = (r ^ 0x5f208c26) & ((1 << 15) - 1);
	return e;
}

static unsigned int reverse_hash_alpha(unsigned int hashX, unsigned int hashY)
{
	unsigned int x = reverse_extend(hashX);
	unsigned int y = reverse_extend(hashY);
	Vec3 res(x, y, 0.0);
	unsigned int angle = reverse_calc(res);
	return angle;
}

static void ShaderMain(unsigned int globalIdX, unsigned int globalIdY)
{
	unsigned int idx=globalIdX+globalIdY*8;
	if ((idx&1)==0)
	{
		std::cout << "idx = " << idx << std::endl;
		
		unsigned int hashValueX = hash[idx];
		unsigned int hashValueY = hash[idx + 1];
		
		std::cout << "hash[idx] = " << hashValueX << std::endl;
		std::cout << "hash[idx + 1] = " << hashValueY << std::endl;
		
		unsigned int h=111;
		//unsigned int h=0x5a;
		//calculate new h somehow before knowing the password
		/*
		for (unsigned int i=0;i<32;i++){
			unsigned int p=password[i];
			unsigned int r=(i*3)&7;
			p=(p<<r)|(p>>(8-r));
			p&=0xff;h^=p;
		}
		*/
		std::cout << "h = " << h << std::endl;
		unsigned int hBitMask = (h|(h<<8)|(h<<16)|(h<<24));
		hashValueX ^= hBitMask;
		hashValueY ^= hBitMask;
		
		std::cout << "hashValueX after idx xoring = " << hashValueX << std::endl;
		std::cout << "hashValueY after idx xoring = " << hashValueY << std::endl;
		
		for (int i=30;i>=0;i-=6)
		{
			hashValueX^=idx<<i;
			hashValueY^=(idx+1)<<i;
		}
		std::cout << "hashValueX after alpha = " << hashValueX << std::endl;
		std::cout << "hashValueY after alpha = " << hashValueY << std::endl;
		password[idx/2]=reverse_hash_alpha(hashValueX, hashValueY);
	}
}


int main()
{	
	std::string outputhash = "30c7ead97107775969be4ba00cf5578f1048ab1375113631dbb6871dbe35162b1c62e982eb6a7512f3274743fb2e55c818912779ef7a34169a838666ff3994bb4d3c6e14ba2d732f14414f2c1cb5d3844935aebbbe3fb206343a004e18a092daba02e3c0969871548ed2c372eb68d1af41152cb3b61f300e3c1a8246108010d282e16df8ae7bff6cb6314d4ad38b5f9779ef23208efe3e1b699700429eae1fa93c036e5dcbe87d32be1ecfac2452ddfdc704a00ea24fbc2161b7824a968e9da1db756712be3e7b3d3420c8f33c37dba42072a941d799ba2eebbf86191cb59aa49a80ebe0b61a79741888cb62341259f62848aad44df2b809383e09437928980f";
	//std::string outputhash = "4a3dc877bd1bd652eca768f889c9f6c44e2c09689d98174933d529188ddab7f6d05aca886e55d46fadae6a3bc8cf74e02bb70baf6a42151ca9b8ab5accd93588ecadccd589cdd21cfce5ecd70bdcf33c5e6c8d63a94a9346f8f62dec9d98b3d0525dce7481e9d0552fa4ee0491ab70eac40b8f9c7a04917bb9ff2f2fdc9e31f40705c08346f0de30850a6076e06bfea4d87e81e1bd1e9f28c836a1e33f0fbe08629f425f95b95c7ac405e2d0a16b7cec668e8340b53a9d611b77a330a5783ddee8b944b056b65a57954de403f02cfad81354859752a19b24915b2562f43abbb0c40f46fda16f5834d44766ff237e791476ce074b81e8196ed054a7c4b53a39f8";
	for(int i = 0; i < hashSize; ++i)
	{
		std::string substring = outputhash.substr(i*8, 8);
		std::stringstream ss;
		ss << std::hex << substring;
		ss >> hash[i];
	}
	
	for(int y = 0; y < 8; ++y)
	{
		for(int x = 0; x < 8; ++x)
		{
			ShaderMain(x, y);
		}
	}
	
	std::cout << "hash:" << std::endl;
	for(int i = 0; i < hashSize; ++i)
	{
		std::cout << std::setfill('0') << std::setw(8) << std::hex << hash[i];
	}
	std::cout << std::endl;
	
	std::cout << "password:" << std::endl;
	for(int i = 0; i < passwordSize; ++i)
	{
		std::cout << char(password[i]);
	}
}