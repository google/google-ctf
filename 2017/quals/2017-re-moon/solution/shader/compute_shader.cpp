#define GLFW_DLL
#include <GL/glew.h>
#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

#define GL_CHECK() \
{\
    GLenum err = glGetError(); \
    if (err != GL_NO_ERROR) \
    {\
        printf("glGetError returns %d\n", err); \
    }\
}

static unsigned int ConmpileShader(GLenum type, const std::string & source)
{
	unsigned int id = glCreateShader(type);
	const char* src = source.c_str();
	glShaderSource(id, 1, &src, nullptr);
	glCompileShader(id);
	int result;
	glGetShaderiv(id, GL_COMPILE_STATUS, &result);
	if(result == GL_FALSE)
	{
		int length;
		glGetShaderiv(id, GL_INFO_LOG_LENGTH, &length);
		char* message = (char *)alloca(length * sizeof(char));
		glGetShaderInfoLog(id, length, &length, message);
		std::cout << "failed to compile shader (" << type << ": " << message << std::endl;
		glDeleteShader(id);
		return 0;
	}
	return id;
}

static unsigned int CreateBuffer(unsigned int uniqueIndex, unsigned int * bufferStart, unsigned int size)
{
	unsigned int ssbo;
	glGenBuffers(1, &ssbo);
	glBindBuffer(GL_SHADER_STORAGE_BUFFER, ssbo);
	glBufferData(GL_SHADER_STORAGE_BUFFER, size * sizeof(unsigned int), bufferStart, GL_STATIC_DRAW);
	glBindBufferBase(GL_SHADER_STORAGE_BUFFER, uniqueIndex, ssbo);
	return ssbo;
}

static std::string ReadFileToString(const std::string& fileName)
{
	std::ifstream f(fileName); //taking file as inputstream
	std::string str;
	if(f) 
	{
		std::ostringstream ss;
		ss << f.rdbuf(); // reading data
		str = ss.str();
	}
	return str;
}

static bool OpenGLInit()
{
	if(!glfwInit())
	{
		std::cout << "glfwInit() failed" << std::endl;
		return false;
	}
	GLFWwindow* window = glfwCreateWindow(640, 480, "Hello World", NULL, NULL);
	if(!window)
	{
		std::cout << "failed to created OpenGL window" << std::endl;
		return false;
	}
	glfwMakeContextCurrent(window);
	if(glewInit() != GLEW_OK)
	{
		std::cout << "glewInit() failed" << std::endl;
		return false;
	}	
	GL_CHECK();
	return true;
}

static bool HandleInputPath(std::string * shaderSource, int argc, char *argv[])
{
	if( argc < 2 )
	{
		std::cout << "No shader source code provided. Expected program to be called as follows:" << std::endl;
		std::cout << "compute_shader.exe COMPUTE_SHADER.COMP" << std::endl;
		return false;
	}
	std::string shaderPath = argv[1];
	*shaderSource = ReadFileToString(shaderPath);
	if( shaderSource->empty() )
	{
		std::cout << "failed to read shader source code from: " << shaderPath << std::endl;
		return false;
	}
	return true;
}

static bool CompileShader( unsigned int * programId, std::string & shaderSource)
{
	unsigned int shaderProgram = glCreateProgram();
	*programId = shaderProgram;
	unsigned int cs = ConmpileShader(GL_COMPUTE_SHADER, shaderSource);
	glAttachShader(shaderProgram, cs);
	glLinkProgram(shaderProgram);
	glValidateProgram(shaderProgram);
	glDeleteShader(cs);
	GL_CHECK();
	return true;
}

int main(int argc, char *argv[]) 
{
	std::cout << "setting up openGL" << std::endl;
	if( OpenGLInit() == false)
	{
		glfwTerminate();
		return -1;
	}
	std::string computeShader;
	if( HandleInputPath(&computeShader, argc, argv) == false )
	{
		glfwTerminate();
		return -1;
	}
	std::cout << "Setup successful. OpenGL version: " << glGetString(GL_VERSION) << std::endl;
	
	//setup shared memory buffers
	std::cout << "setting up memory buffers" << std::endl;
	
	const unsigned int stateSize = 64;
	const unsigned int hashSize = 64;
	const unsigned int passwordSize = 32;
	const unsigned int bufferSize = stateSize + hashSize + passwordSize;
	struct InputBuffer 
	{
		unsigned int state[stateSize];
		unsigned int hash[hashSize];
		unsigned int password[passwordSize];
	};
	union InputUnion
	{
		InputBuffer shaderExchange;
		unsigned int rawMemory[bufferSize];
	} superBuffer;
	for( int i = 0; i < bufferSize; ++i )
	{
		superBuffer.rawMemory[i] = 0;
	}
	for( int i = 0; i < stateSize; ++i )
	{
		superBuffer.shaderExchange.state[i] = 1;
	}
	std::string inputValues = "12345678901234567890123456789012";
	for(int i = 0; i < inputValues.size(); ++i)
	{
		superBuffer.shaderExchange.password[i] = inputValues[i];
	}
	std::cout << superBuffer.shaderExchange.password[1] << std::endl;
	
	
	//tell gpu about memory buffer
	unsigned int outputBufferId = CreateBuffer(0, &superBuffer.rawMemory[0], bufferSize);
	std::cout << "successfully created buffers" << std::endl;
	
	
	std::cout << "compiling shader" << std::endl;
	unsigned int shaderProgram = 0;
	if(CompileShader(&shaderProgram, computeShader) == false)
	{
		glfwTerminate();
		return -1;
	}
	std::cout << "successfully compiled shader" << std::endl;
	
	//execute shader
	std::cout << "executing shader" << std::endl;
	glUseProgram(shaderProgram);
	unsigned int xBatches = 1;
	unsigned int yBatches = 1;
	unsigned int zBatches = 1;
	glDispatchCompute(xBatches, yBatches, zBatches);
	glMemoryBarrier(GL_SHADER_STORAGE_BARRIER_BIT);
	GL_CHECK();
	
	//read results
	std::cout << "printing results" << std::endl;
	glBindBuffer(GL_SHADER_STORAGE_BUFFER, outputBufferId);
	unsigned int * outputBuffer = (unsigned int *)glMapBufferRange(GL_SHADER_STORAGE_BUFFER, 0, bufferSize * sizeof(unsigned int), GL_MAP_READ_BIT);
	InputUnion * superOutput = (InputUnion *) outputBuffer;
	std::cout << "State:" << std::endl;
	for(int i = 0; i < stateSize; ++i)
	{
		std::cout << std::hex << superOutput->shaderExchange.state[i];
	}
	std::cout << std::endl;
	
	std::cout << "Hash:" << std::endl;
	for(int i = 0; i < hashSize; ++i)
	{
		std::cout << std::hex << superOutput->shaderExchange.hash[i];
	}
	std::cout << std::endl;
	
	std::cout << "Password:" << std::endl;
	for(int i = 0; i < passwordSize; ++i)
	{
		std::cout << std::hex << superOutput->shaderExchange.password[i];
	}
	std::cout << std::endl;
	
	glDeleteProgram(shaderProgram);
	return 0;
}