#ifndef VEC3_H
#define VEC3_H
#include "Mat3.h"

class Vec3
{
	public:
	double x;
	double y;
	double z;
	
	Vec3(const double & x, const double & y, const double & z);
	Vec3 operator* (Mat3 & x);
	void operator+=(Vec3 & rhs);
	double operator[] (int i);
};
#endif