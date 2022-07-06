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
module Challenge(
    input [15:0] a,
    input [15:0] b,
    output res
);
    wire [31:0] mres;
    // Multiplication result, expected inputs 50503 and 50513
    assign mres = a * b;
    assign res = (mres == 32'd2551058039) && a < b;
endmodule
