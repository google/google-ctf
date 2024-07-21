#include "Mat3.h"

Mat3::Mat3(double m00, double m10, double m20, double m01, double m11, double m21, double m02, double m12, double m22)
{
	this->m00 = m00;
	this->m01 = m01;
	this->m02 = m02;
	this->m10 = m10;
	this->m11 = m11;
	this->m12 = m12;
	this->m20 = m20;
	this->m21 = m21;
	this->m22 = m22;
}