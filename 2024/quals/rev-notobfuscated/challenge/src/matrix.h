// Copyright 2024 Google LLC
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

#pragma once

#include <array>

template <const std::size_t M, const std::size_t N, class T>
class Matrix
{
public:
    /*template<typename I>
    explicit Matrix(I begin, I end) {
        for(I itr = begin; itr != end; itr++) {
            values[]
        }
    }
    Matrix(const T& val) : values(val) {}*/

    explicit constexpr Matrix(const T &val)
    {
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                values[y][x] = val;
            }
        }
    }

    template <typename = std::enable_if_t<M == N>>
    static Matrix
    diagonal(const T &val)
    {
        Matrix ret;
        for (int y = 0; y < M; y++)
        {
            ret.values[y][y] = val;
        }
        return ret;
    }

    constexpr Matrix()
    {
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                values[y][x] = T{};
            }
        }
    }

    constexpr Matrix(const Matrix<M, N, T> &other) : values(other.values) {}

    constexpr Matrix(const Matrix<M, N, T> &&other) : values(other.values) {}

    explicit constexpr Matrix(const std::array<std::array<T, N>, M> &data) : values(data) {}

    explicit constexpr Matrix(const std::array<T, N * M> &data)
    {
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                values[y][x] = data[y * M + x];
            }
        }
    }

    void debug_print() const
    {

        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                printf("%d", values);
                if (x + 1 < N)
                {
                    printf(", ");
                }
            }
            printf("\n");
        }
    }

    Matrix &operator+=(const Matrix<M, N, T> &other)
    {
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                values[y][x] += other.values[y][x];
            }
        }

        return *this;
    }

    constexpr Matrix operator+(const Matrix<M, N, T> &other) const
    {
        Matrix result(*this);
        result += other;
        return result;
    }

    Matrix &operator-=(const Matrix<M, N, T> &other)
    {
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                values[y][x] -= other.values[y][x];
            }
        }

        return *this;
    }

    constexpr Matrix operator-(const Matrix<M, N, T> &other) const
    {
        Matrix result(*this);
        result += other;
        return result;
    }

    template <const std::size_t P>
    Matrix<N, P, T> operator*(const Matrix<M, P, T> &other)
    {
        Matrix<N, P, T> result;
        for (size_t i = 0; i < N; i++)
        {
            for (size_t j = 0; j < P; j++)
            {
                for (size_t k = 0; k < M; k++)
                {
                    result.values[i][j] += values[i][k] * other.values[k][j];
                }
            }
        }
        return result;
    }

    std::array<std::array<T, N>, M> get_data() const
    {
        std::array<std::array<T, N>, M> data = values;
        return data;
    }

    std::array<T, N * M> get_vector() const
    {
        std::array<T, N * M> data;
        for (size_t y = 0; y < M; y++)
        {
            for (size_t x = 0; x < N; x++)
            {
                data[y * M + x] = values[y][x];
            }
        }
        return data;
    }

    friend std::ostream &operator<<(std::ostream &os, const Matrix<M, N, T> &rns)
    {
        for (size_t y = 0; y < M; y++)
        {
            os << "[";
            for (size_t x = 0; x < N; x++)
            {
                os << rns.values[y][x];
                if (x + 1 < N)
                {
                    os << ", ";
                }
                else
                {
                    os << "]";
                }
            }
            os << std::endl;
        }

        return os;
    }

private:
    std::array<std::array<T, N>, M> values;
};
