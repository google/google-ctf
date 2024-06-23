// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    "fmt"
    "math/rand"
    "testing"
)

func mul(a, b int) int {
    if a == 0 {
        a = 65536
    }
    if b == 0 {
        b = 65536
    }
    return (a * b % 65537) & 0xffff
}



func mul_fast16(a, b uint16) uint16 {
    if a == 0 {
        return 0xffff - b + 1 
    }
    if b == 0 {
        return 0xffff - a + 1 
    }

    c := uint32(a) * uint32(b)
    c0 := uint16(c >> 32)
    ch := uint16(c >> 16)  
    cl := uint16(c)

    if cl >= ch {
        return uint16(cl - ch + c0)
    }
    return uint16(cl - ch + 1) 
}


func mul_fast32(a, b int) int {
    if a == 0 {
        return 0x10001 - b 
    }
    if b == 0 {
        return 0x10001 - a 
    }

    c := a*b
    c0 := (c >> 32)&0xffff
    ch := (c >> 16)&0xffff  
    cl := (c)&0xffff

    if cl >= ch {
        return cl - ch + c0
    }
    return (cl - ch + 1)&0xffff 
}



func BenchmarkMulFast16(b *testing.B) {
    inputA := make([]uint16, b.N)
    inputB := make([]uint16, b.N)
    for i := 0; i < b.N; i++ {
        inputA[i] = uint16(rand.Intn(65536)) 
        inputB[i] = uint16(rand.Intn(65536))
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = mul_fast16(inputA[i], inputB[i])
    }
}


func BenchmarkMul(b *testing.B) {
    inputA := make([]int, b.N)
    inputB := make([]int, b.N)
    for i := 0; i < b.N; i++ {
        inputA[i] = rand.Intn(65536) 
        inputB[i] = rand.Intn(65536)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = mul(inputA[i], inputB[i]) // Use _ to discard the result
    }
}

func BenchmarkMulFast32(b *testing.B) {
    inputA := make([]int, b.N)
    inputB := make([]int, b.N)
    for i := 0; i < b.N; i++ {
        inputA[i] = rand.Intn(65536) 
        inputB[i] = rand.Intn(65536)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = mul_fast32(inputA[i], inputB[i]) 
    }
}

func main() {
    fmt.Println(testing.Benchmark(BenchmarkMul))
    fmt.Println(testing.Benchmark(BenchmarkMulFast16))
    fmt.Println(testing.Benchmark(BenchmarkMulFast32))
}

