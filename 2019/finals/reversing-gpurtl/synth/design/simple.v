module counter(clock, out);

input clock;
output reg [8:0] out;

always @(posedge clock)
begin
	out <= out + 1;
end

endmodule
