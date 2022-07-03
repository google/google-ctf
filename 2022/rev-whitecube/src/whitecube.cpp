// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Carl Svensson

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <string>
#include <iostream>
#include <iterator>
#include <vector>
#include <fstream>
#include <vector>
#include <array>
#include <random>

#include "shaders/shader_vert.h"
#include "shaders/shader_frag.h"

#define STRICT
//#define TEST

const unsigned int SCR_WIDTH = 800;
const unsigned int SCR_HEIGHT = 640;

void GLAPIENTRY
MessageCallback( GLenum source,
                 GLenum type,
                 GLuint id,
                 GLenum severity,
                 GLsizei length,
                 const GLchar* message,
                 const void* userParam )
{
    std::cerr << "GL CALLBACK: " << (type == GL_DEBUG_TYPE_ERROR ? "** GL ERROR **" : "") << " type = 0x" << std::hex << type << ", severity = 0x" << std::hex << severity << ", message = " << message << std::endl;
}


bool init() {
    if (GLFW_TRUE != glfwInit()) {
        std::cerr << "Failed to init GLFW" << std::endl;
        return false;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 6);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    return true;
}

GLFWwindow* init_window() {
    GLFWwindow* window = glfwCreateWindow(SCR_WIDTH, SCR_HEIGHT, "Whitecube", NULL, NULL);
    if (window == nullptr)
    {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return nullptr;
    }
    glfwMakeContextCurrent(window);
    
    if (!gladLoadGLLoader((GLADloadproc)glfwGetProcAddress))
    {
        std::cerr << "Failed to initialize GLAD" << std::endl;
        return nullptr;
    }
    glEnable              ( GL_DEBUG_OUTPUT );
    glDebugMessageCallback( MessageCallback, 0 );

    return window;
}

GLuint CompileShader(const GLuint shader_type, const char* const entrypoint, const uint32_t * const shader_data, const GLsizei shader_size) {
    GLint isCompiled = 0;

    const GLuint shader = glCreateShader(shader_type);
    if (shader == 0) {
        std::cerr << "failed to create vertex shader" << std::endl;
    }

    glShaderBinary(1, &shader, GL_SHADER_BINARY_FORMAT_SPIR_V, shader_data, shader_size);
    glSpecializeShader(shader, entrypoint, 0, nullptr, nullptr);

    glGetShaderiv(shader, GL_COMPILE_STATUS, &isCompiled);
    if (isCompiled == GL_FALSE)
    {
        GLint maxLength = 0;
        glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &maxLength);

        std::vector<GLchar> infoLog(maxLength);
        glGetShaderInfoLog(shader, maxLength, &maxLength, &infoLog[0]);
        glDeleteShader(shader);
        std::cerr << infoLog.data() << std::endl;
    }

    return shader;
}

GLuint BuildShaderProgram(const GLuint vertexShader, const GLuint fragmentShader) {
    GLuint shaderProgram = glCreateProgram();
    glAttachShader(shaderProgram, vertexShader);
    glAttachShader(shaderProgram, fragmentShader);
    glLinkProgram(shaderProgram);

    GLint isLinked = 0;
    glGetProgramiv(shaderProgram, GL_LINK_STATUS, &isLinked);
    if (isLinked == GL_FALSE)
    {
        GLint maxLength = 0;
        glGetProgramiv(shaderProgram, GL_INFO_LOG_LENGTH, &maxLength);

        std::vector<GLchar> infoLog(maxLength);
        glGetProgramInfoLog(shaderProgram, maxLength, &maxLength, &infoLog[0]);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(fragmentShader);
        std::cerr << infoLog.data() << std::endl;
    }
    glDetachShader(shaderProgram, vertexShader);
    glDetachShader(shaderProgram, fragmentShader);

    return shaderProgram;
}

GLuint UpdateSSBO(GLuint ssbo, const std::vector<float>& varray)
{
    glBindBuffer(GL_SHADER_STORAGE_BUFFER, ssbo);
    glBufferData(GL_SHADER_STORAGE_BUFFER, varray.size() * sizeof(*varray.data()), varray.data(), GL_STATIC_DRAW);
    return ssbo;
}

GLuint CreateSSBO(const std::vector<float>& varray)
{
    GLuint ssbo;
    glGenBuffers(1, &ssbo);
    return UpdateSSBO(ssbo, varray);
}

int main(int argc, char **argv, char **envp)
{
#ifdef TEST
    const std::string input_file_path = "test.in";
    const std::string output_file_path = "test.out";
#else
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
        return EXIT_FAILURE;
    }

    const std::string input_file_path(argv[1]);
    const std::string output_file_path(argv[2]);
#endif

    std::ifstream fin(input_file_path, std::ios::in | std::ios::binary);
    if (fin.fail()) {
        std::cerr << "Failed to open \"" << input_file_path << "\" for reading. Exiting." << std::endl;
        return EXIT_FAILURE;
    }
    std::ofstream fout(output_file_path, std::ios::out | std::ios::binary);
    if (fin.fail()) {
        std::cerr << "Failed to open \"" << output_file_path << "\" for writing. Exiting." << std::endl;
        return EXIT_FAILURE;
    }

    fin.seekg(0, std::ios::end);
    const size_t fin_size = fin.tellg();
    fin.seekg(0, std::ios::beg);
    const size_t num_blocks = (fin_size + 1023) / 1024;

    if (fin_size > 4 * SCR_WIDTH * SCR_HEIGHT) {
        std::cerr << "Input file too large. Please buy the premium version to enable encryption of larger files. Exiting." << std::endl;
        return EXIT_FAILURE;
    }

    const std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());

    if (!init()) {
        std::cerr << "Failed to init. Exiting" << std::endl;
        return EXIT_FAILURE;
    }
    GLFWwindow* window = init_window();
    if (!window) {
        return EXIT_FAILURE;
    }

    const GLuint vertexShader = CompileShader(GL_VERTEX_SHADER, "main", shader_vert, sizeof(shader_vert));
    const GLuint fragmentShader = CompileShader(GL_FRAGMENT_SHADER, "main", shader_frag, sizeof(shader_frag));
    const GLuint shaderProgram = BuildShaderProgram(vertexShader, fragmentShader);

    const GLint location_block_count = glGetUniformLocation(shaderProgram, "u_block_count");

#ifdef STRICT
    if (location_block_count == -1) {
        std::cerr << "failed to fetch uniform location for u_block_count. Exiting" << std::endl;
        return EXIT_FAILURE;
    }
#endif

    const GLint location_resolution = glGetUniformLocation(shaderProgram, "u_resolution");

#ifdef STRICT
    if (location_resolution == -1) {
        std::cerr << "failed to fetch uniform location for u_resolution. Exiting" << std::endl;
        return EXIT_FAILURE;
    }
#endif

    const GLint location_nonce = glGetUniformLocation(shaderProgram, "u_nonce");
#ifdef STRICT
    if (location_nonce == -1) {
        std::cerr << "failed to fetch uniform location for u_nonce. Exiting" << std::endl;
        return EXIT_FAILURE;
    }
#endif

    glUseProgram(shaderProgram);

#ifndef STRICT
    if (location_resolution != -1)
#endif // !STRICT
    glUniform2ui(location_resolution, SCR_WIDTH, SCR_HEIGHT);

#ifndef STRICT
    if (location_block_count != -1)
#endif // !STRICT
    glUniform1ui(location_block_count, static_cast<GLuint>(num_blocks));

    // TODO: randomly generated, needs to be invertible
    // Column-major 16x16 identity matrix
    std::vector<GLfloat> nonce_matrix = {
        1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,
        1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f,
    };
    const std::vector<size_t> diagonal_indices = {
          0,   5,  10,  15,
         80,  85,  90,  95,
        160, 165, 170, 175,
        240, 245, 250, 255
    };

    std::array<uint_fast32_t, 8> random_data;
    std::random_device random_source;
    std::generate(random_data.begin(), random_data.end(), std::ref(random_source));
    std::seed_seq seed_seq(random_data.begin(), random_data.end());
    std::mt19937 generator{ seed_seq };
    std::uniform_int_distribution<int> distribution(1, 128);
    std::vector<uint8_t> nonce_vec(12);
    for (size_t i = 0; i < 12; i++) {
        nonce_vec[i] = (2*distribution(generator) - 1);
        nonce_matrix[diagonal_indices[i]] = (float)nonce_vec[i];
    }
    fout.write(reinterpret_cast<const char*>(&fin_size), sizeof(fin_size));
    fout.write((char*)nonce_vec.data(), 12 * sizeof(std::uint8_t));

#ifndef STRICT
    if (location_nonce != -1)
#endif // !STRICT
    glUniformMatrix4fv(location_nonce, 4 * 4, GL_FALSE, nonce_matrix.data());

    // Create column-major matrix from input data
    std::vector<float> varray(SCR_HEIGHT * SCR_WIDTH * 4, 0.0f);
    for (size_t i = 0; i < fin_size; i++) {
        const size_t matrix = i / (4ull * 4);
        const size_t matrix_i = i % (4ull * 4);
        const size_t col = matrix_i / 4;
        const size_t row = matrix_i % 4;
        varray[(4ull * 4) * matrix + 4 * row + col] = (float)input_data[i]; //(float)(i % 256);
    }
   
    // set up vertex data (and buffer(s)) and configure vertex attributes
    const float vertices[] = {
         1.0f,  1.0f, 0.0f,  // top right
         1.0f, -1.0f, 0.0f,  // bottom right
        -1.0f, -1.0f, 0.0f,  // bottom left
        -1.0f,  1.0f, 0.0f   // top left 
    };
    const GLuint indices[] = {
        0, 1, 3,  // first Triangle
        1, 2, 3   // second Triangle
    };
    GLuint VBO, VAO, EBO;
    glGenVertexArrays(1, &VAO);
    glGenBuffers(1, &VBO);
    glGenBuffers(1, &EBO);
    // bind the Vertex Array Object first, then bind and set vertex buffer(s), and then configure vertex attributes(s).
    glBindVertexArray(VAO);

    const GLuint ssbo = CreateSSBO(varray);
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, ssbo);

    glBindBuffer(GL_ARRAY_BUFFER, VBO);
    glBufferData(GL_ARRAY_BUFFER, sizeof(vertices), vertices, GL_STATIC_DRAW);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, EBO);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(indices), indices, GL_STATIC_DRAW);

    glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * sizeof(float), nullptr);
    glEnableVertexAttribArray(0);

    // note that this is allowed, the call to glVertexAttribPointer registered VBO as the vertex attribute's bound vertex buffer object so afterwards we can safely unbind
    glBindBuffer(GL_ARRAY_BUFFER, 0); 

    // remember: do NOT unbind the EBO while a VAO is active as the bound element buffer object IS stored in the VAO; keep the EBO bound.
    //glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);

    // You can unbind the VAO afterwards so other VAO calls won't accidentally modify this VAO, but this rarely happens. Modifying other
    // VAOs requires a call to glBindVertexArray anyways so we generally don't unbind VAOs (nor VBOs) when it's not directly necessary.
    glBindVertexArray(0); 

    std::vector<std::uint8_t> screen_data(SCR_WIDTH * SCR_HEIGHT * 4);

    for (int i = 0; i < 8; i++)
    {
        
        glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        glUseProgram(shaderProgram);
           

        glBindVertexArray(VAO); // seeing as we only have a single VAO there's no need to bind it every time, but we'll do so to keep things a bit more organized
        //glDrawArrays(GL_TRIANGLES, 0, 6);
        glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);

        glReadBuffer(GL_BACK);
        glReadPixels(0, 0, SCR_WIDTH, SCR_HEIGHT, GL_RGBA, GL_UNSIGNED_BYTE, screen_data.data());

        // Copy the data into the next round
        for (size_t i = 0; i < 4ull * SCR_WIDTH * SCR_HEIGHT; i++) {
            varray[i] = 0.0f;
        }
        for (size_t i = 0; i < (num_blocks*1024); i++) {
            const size_t matrix = i / (4ull * 4);
            const size_t matrix_i = i % (4ull * 4);
            const size_t col = matrix_i / 4;
            const size_t row = matrix_i % 4;
            varray[(4ull * 4) * matrix + 4 * row + col] = (float)screen_data[i];
        }
        UpdateSSBO(ssbo, varray);

        glfwSwapBuffers(window);
        glfwPollEvents();
    }

    // Write data to disk
    fout.write((char*)screen_data.data(), (num_blocks * 1024) * sizeof(std::uint8_t));
    fout.close();

    // Cleanup
    glDeleteVertexArrays(1, &VAO);
    glDeleteBuffers(1, &VBO);
    glDeleteBuffers(1, &EBO);
    glDeleteProgram(shaderProgram);

    glfwDestroyWindow(window);
    glfwTerminate();
    return EXIT_SUCCESS;
}
