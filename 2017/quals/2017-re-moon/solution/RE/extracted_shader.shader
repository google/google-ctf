#version 430
layout(local_size_x=8,local_size_y=8)in;
layout(std430,binding=0) buffer shaderExchangeProtocol{
	uint state[64];
	uint hash[64];
	uint password[32];
};

vec3 calc(uint p){
	float r=radians(p);
	float c=cos(r);
	float s=sin(r);
	mat3 m=mat3(c,-s,0.0,s,c,0.0,0.0,0.0,1.0);
	vec3 pt=vec3(1024.0,0.0,0.0);
	vec3 res=m*pt;
	res+=vec3(2048.0,2048.0,0.0);
	return res;
}

uint extend(uint e){
	uint i;
	uint r=e^0x5f208c26;
	for (i=15;i<31;i+=3){
		uint f=e<<i;
		r^=f;
	}
	return r;
}

uint hash_alpha(uint p){
	vec3 res=calc(p);
	return extend(uint(res[0]));
}

uint hash_beta(uint p){
	vec3 res=calc(p);
	return extend(uint(res[1]));
}

void main(){
	uint idx=gl_GlobalInvocationID.x+gl_GlobalInvocationID.y*8;
	uint final;
	if (state[idx]!=1){
		return;
	}if ((idx&1)==0){
		final=hash_alpha(password[idx/2]);
	}else{
		final=hash_beta(password[idx/2]);
	}
	uint i;
	for (i=0;i<32;i+=6){
		final^=idx<<i;
	}
	
	uint h=0x5a;
	for (i=0;i<32;i++){
		uint p=password[i];
		uint r=(i*3)&7;
		p=(p<<r)|(p>>(8-r));
		p&=0xff;h^=p;
	}
	
	final^=(h|(h<<8)|(h<<16)|(h<<24));
	
	hash[idx]=final;
	
	state[idx]=2;
	memoryBarrierShared();
}