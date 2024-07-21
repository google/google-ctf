#include "Vec3.h"

Vec3::Vec3(const double & x, const double & y, const double & z)
{
	this->x = x;
	this->y = y;
	this->z = z;
}

Vec3 Vec3::operator* (Mat3 & mat)
{
	double x = mat.m00 * this->x + mat.m01 * this->y + mat.m02 * this->z;
	double y = mat.m10 * this->x + mat.m11 * this->y + mat.m12 * this->z;
	double z = mat.m20 * this->x + mat.m21 * this->y + mat.m22 * this->z;
	
	Vec3 * resultVec = new Vec3(x, y, z);
	return *resultVec;
}

void Vec3::operator+=(Vec3 & rhs)
{
	this->x += rhs.x;
	this->y += rhs.y;
	this->z += rhs.z;
}

double Vec3::operator[] (int i)
{
	if(i == 0)
	{
		return this->x;
	} 
	else if( i == 1 )
	{
		return this->y;
	} 
	else if( i == 2 )
	{
		return this->z;
	}
	
	return 0.0;
}