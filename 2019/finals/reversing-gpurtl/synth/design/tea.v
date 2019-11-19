/* Copyright 2019 Google LLC */

/* Licensed under the Apache License, Version 2.0 (the "License"); */
/* you may not use this file except in compliance with the License. */
/* You may obtain a copy of the License at */

/*     https://www.apache.org/licenses/LICENSE-2.0 */

/* Unless required by applicable law or agreed to in writing, software */
/* distributed under the License is distributed on an "AS IS" BASIS, */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/* See the License for the specific language governing permissions and */
/* limitations under the License. */

module toplevel (
	input clock,
	input [255:0] plain,
	output [255:0] cipher,
	output done,
);

	reg [3:0] state = 0;
	reg [255:0] out;

	wire [63:0] mod_in;
	wire mod_in_ready;
	wire mod_in_ack;
	wire [63:0] mod_out;
	wire mod_out_ready;
	wire mod_out_ack;

	tea_encrypt mod (
		.clock(clock),
		.in(mod_in),
		.in_ready(mod_in_ready),
		.in_ack(mod_in_ack),
		.out(mod_out),
		.out_ready(mod_out_ready),
		.out_ack(mod_out_ack),
	);

	always @* begin
		case (state)
			0: mod_in = plain[255:192];
			2: mod_in = plain[191:128];
			4: mod_in = plain[127:64];
			6: mod_in = plain[63:0];
			default: mod_in = 0;
		endcase
	end

	assign mod_out_ack = (state == 1 || state == 3 || state == 5 || state == 7);
	assign mod_in_ready = (state == 0 || state == 2 || state == 4 || state == 6);

	assign done = (state == 8);
	assign cipher = out;

	always @(posedge clock) begin
		case (state)
			0: begin
				if (mod_in_ack) state <= 1;
			end
			1: begin
				if (mod_out_ready) state <= 2;
				out[255:192] <= mod_out;
			end
			2: begin
				if (mod_in_ack) state <= 3;
			end
			3: begin
				if (mod_out_ready) state <= 4;
				out[191:128] <= mod_out;
			end
			4: begin
				if (mod_in_ack) state <= 5;
			end
			5: begin
				if (mod_out_ready) state <= 6;
				out[127:64] <= mod_out;
			end
			6: begin
				if (mod_in_ack) state <= 7;
			end
			7: begin
				if (mod_out_ready) state <= 8;
				out[63:0] <= mod_out;
			end
		endcase
	end
endmodule

module tea_encrypt (
	input clock,
	input [63:0] in,
	input in_ready,
	output in_ack,
	output [63:0] out,
	output out_ready,
	input out_ack,
);
	reg [31:0] v0, v1, sum;
	reg [31:0] delta = 32'h9e3779b9;

	localparam [127:0] k = "FancyACupOfTEA??";
	localparam [31:0] k0 = k[127:96];
	localparam [31:0] k1 = k[95:64];
	localparam [31:0] k2 = k[63:32];
	localparam [31:0] k3 = k[31:0];

	reg [1:0] state = 0;
	reg [6:0] iter = 0;

	assign in_ack = (state == 0);
	assign out_ready = (state == 2);
	assign out[63:32] = v0;
	assign out[31:0] = v1;

	always @(posedge clock) begin
		case (state)
			0: begin
				if (in_ready) state <= 1;
				v0 <= in[63:32];
				v1 <= in[31:0];
				iter <= 0;
				sum <= delta;
			end
			1: begin
				iter <= iter + 1;
				if (iter == 63) state <= 2;

				if (iter % 2 == 0) begin
					v0 <= v0 + (((v1 <<< 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1));
				end else begin
					v1 <= v1 + (((v0 <<< 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3));
					sum <= sum + delta;
				end
			end
			2: begin
				if (out_ack) state <= 0;
			end
		endcase
	end
endmodule
