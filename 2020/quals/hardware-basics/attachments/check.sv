/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
module check(
    input clk,

    input [6:0] data,
    output wire open_safe
);

reg [6:0] memory [7:0];
reg [2:0] idx = 0;

wire [55:0] magic = {
    {memory[0], memory[5]},
    {memory[6], memory[2]},
    {memory[4], memory[3]},
    {memory[7], memory[1]}
};

wire [55:0] kittens = { magic[9:0],  magic[41:22], magic[21:10], magic[55:42] };
assign open_safe = kittens == 56'd3008192072309708;

always_ff @(posedge clk) begin
    memory[idx] <= data;
    idx <= idx + 5;
end

endmodule

