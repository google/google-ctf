// Copyright 2019 Google LLC
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

// Secure EEPROM

`ifdef DEBUG
  `define DEBUG_DISPLAY(_args) $display("%s", $sformatf _args);
`else
  `define DEBUG_DISPLAY(_args)
`endif

module seeprom (
  input i_clk,
  input logic i_i2c_scl,
  input logic i_i2c_sda,
  output logic o_i2c_sda
);

initial begin
  o_i2c_sda = 1;
  i2c_state = I2C_IDLE;
  mem_secure = 0;
  i2c_scl_state = I2C_SCL_STABLE_HIGH;
  i2c_address_valid = 0;
end

/* verilator lint_off UNDRIVEN */
enum {
  I2C_IDLE,
  I2C_START,
  I2C_LOAD_CONTROL,
  I2C_ACK_THEN_LOAD_ADDRESS,
  I2C_ACK_THEN_READ,
  I2C_ACK_THEN_WRITE,
  I2C_LOAD_ADDRESS,
  I2C_READ,
  I2C_WRITE,
  I2C_ACK,
  I2C_NACK
} i2c_state;
/* verilator lint_on UNDRIVEN */

logic [255:0][7:0] mem_storage;
logic [3:0] mem_secure;

logic [7:0] i2c_control;
logic [3:0] i2c_control_bits;
logic [7:0] i2c_address;
logic [3:0] i2c_address_bits;
logic       i2c_address_valid;
logic [7:0] i2c_data;
logic [3:0] i2c_data_bits;

wire i2c_address_secure = mem_secure[i2c_address / 64];
wire i2c_next_address_secure = mem_secure[(i2c_address + 1) / 64];

wire [3:0] i2c_control_prefix = i2c_control[7:4];
wire [3:0] i2c_control_bank = i2c_control[3:0];
wire i2c_control_rw = i2c_control[0];

`define I2C_CONTROL_EEPROM 4'b1010
`define I2C_CONTROL_SECURE 4'b0101

logic i2c_last_scl;
logic i2c_last_sda;

always_ff @(posedge i_clk) begin
  i2c_last_scl <= i_i2c_scl;
  i2c_last_sda <= i_i2c_sda;
end

/* verilator lint_off UNDRIVEN */
enum {
  I2C_SCL_STABLE_HIGH,
  I2C_SCL_STABLE_LOW,
  I2C_SCL_FALLING,
  I2C_SCL_RISING
} i2c_scl_state;
/* verilator lint_on UNDRIVEN */

always_comb begin
  if (i2c_last_scl && i_i2c_scl) begin
    i2c_scl_state = I2C_SCL_STABLE_HIGH;
  end else if (!i2c_last_scl && !i_i2c_scl) begin
    i2c_scl_state = I2C_SCL_STABLE_LOW;
  end else if (i2c_last_scl && !i_i2c_scl) begin
    i2c_scl_state = I2C_SCL_FALLING;
  end else if (!i2c_last_scl && i_i2c_scl) begin
    i2c_scl_state = I2C_SCL_RISING;
  end
end

wire i2c_start;
wire i2c_stop;

always_comb begin
  if (i2c_scl_state == I2C_SCL_STABLE_HIGH) begin
    i2c_start = i2c_last_sda && !i_i2c_sda;
    i2c_stop = !i2c_last_sda && i_i2c_sda;
  end else begin
    i2c_start = 0;
    i2c_stop = 0;
  end
end

`define ACK_THEN_TRANSITION(_ack, _next_state) \
  begin \
    if (i2c_scl_state == I2C_SCL_FALLING) begin \
      o_i2c_sda <= _ack; \
    end else if (i2c_scl_state == I2C_SCL_RISING) begin \
      i2c_state <= _next_state; \
    end \
  end

always_ff @(posedge i_clk) begin
  `DEBUG_DISPLAY(("i2c_state = %s", i2c_state.name));
  `DEBUG_DISPLAY(("i2c_scl_state = %s", i2c_scl_state.name));
  `DEBUG_DISPLAY(("i2c_address_valid = %b", i2c_address_valid));
  `DEBUG_DISPLAY(("mem_secure = %b", mem_secure));
  case (i2c_state)
    I2C_IDLE: begin
      if (i2c_start) begin
        i2c_state <= I2C_START;
      end
    end
    I2C_START: begin
      if (i2c_scl_state == I2C_SCL_FALLING) begin
        i2c_control_bits <= 0;
        i2c_state <= I2C_LOAD_CONTROL;
      end
    end
    I2C_LOAD_CONTROL: begin
      `DEBUG_DISPLAY(("i2c_control = %b", i2c_control));
      `DEBUG_DISPLAY(("i2c_control_bits = %d", i2c_control_bits));
      if (i2c_control_bits == 8) begin
        case (i2c_control_prefix)
          `I2C_CONTROL_EEPROM: begin
            if (i2c_control_rw) begin
              if (i2c_address_valid) begin
                i2c_data_bits <= 0;
                i2c_state <= I2C_ACK_THEN_READ;
              end else begin
                i2c_state <= I2C_NACK;
              end
            end else begin
              i2c_address_bits <= 0;
              i2c_state <= I2C_ACK_THEN_LOAD_ADDRESS;
            end
          end
          `I2C_CONTROL_SECURE: begin
            mem_secure <= mem_secure | i2c_control_bank;
            i2c_state <= I2C_ACK;
          end
          default: begin
            i2c_state <= I2C_NACK;
          end
        endcase
        i2c_control_bits <= 0;
      end else if (i2c_scl_state == I2C_SCL_RISING) begin
        i2c_control <= {i2c_control[6:0], i_i2c_sda};
        i2c_control_bits <= i2c_control_bits + 1;
      end
    end
    I2C_LOAD_ADDRESS: begin
      `DEBUG_DISPLAY(("i2c_address = %b", i2c_address));
      `DEBUG_DISPLAY(("i2c_address_bits = %d", i2c_address_bits));
      if (i2c_address_bits == 8) begin
        if (i2c_address_secure) begin
          i2c_address_valid <= 0;
          i2c_state <= I2C_NACK;
        end else begin
          i2c_data_bits <= 0;
          i2c_address_valid <= 1;
          i2c_state <= I2C_ACK_THEN_WRITE;
        end
      end else if (i2c_scl_state == I2C_SCL_RISING) begin
        i2c_address <= {i2c_address[6:0], i_i2c_sda};
        i2c_address_bits <= i2c_address_bits + 1;
      end
    end
    I2C_WRITE: begin
      `DEBUG_DISPLAY(("i2c_data_ = %b", i2c_data));
      `DEBUG_DISPLAY(("i2c_data_bits = %d", i2c_data_bits));
      if (i2c_data_bits == 8) begin
        i2c_data_bits <= 0;
        if (i2c_address_secure == i2c_next_address_secure) begin
          `DEBUG_DISPLAY(("WRITE: i2c_address = 0x%x, i2c_data = 0x%x", i2c_address, i2c_data));
          mem_storage[i2c_address] <= i2c_data;
          i2c_address <= i2c_address + 1;
          i2c_state <= I2C_ACK_THEN_WRITE;
        end else begin
          i2c_state <= I2C_NACK;
        end
      end else if (i2c_scl_state == I2C_SCL_RISING) begin
        i2c_data <= {i2c_data[6:0], i_i2c_sda};
        i2c_data_bits <= i2c_data_bits + 1;
      end
    end
    I2C_READ: begin
      `DEBUG_DISPLAY(("i2c_data_bits = %d", i2c_data_bits));
      if (i2c_data_bits == 8 && i2c_scl_state == I2C_SCL_RISING) begin
        i2c_data_bits <= 0;
        if (i2c_address_secure == i2c_next_address_secure) begin
          `DEBUG_DISPLAY(("READ: i2c_address = 0x%x", i2c_address));
          i2c_address <= i2c_address + 1;
          i2c_state <= I2C_ACK_THEN_READ;
        end else begin
          i2c_state <= I2C_NACK;
        end
      end else if (i2c_scl_state == I2C_SCL_FALLING) begin
        `DEBUG_DISPLAY(("READ (bit): i2c_address = 0x%x", i2c_address));
        o_i2c_sda <= mem_storage[i2c_address][7 - i2c_data_bits[2:0]];
        i2c_data_bits <= i2c_data_bits + 1;
      end
    end
    I2C_ACK: `ACK_THEN_TRANSITION(0, I2C_IDLE)
    I2C_ACK_THEN_LOAD_ADDRESS: `ACK_THEN_TRANSITION(0, I2C_LOAD_ADDRESS)
    I2C_ACK_THEN_READ: `ACK_THEN_TRANSITION(0, I2C_READ)
    I2C_ACK_THEN_WRITE: `ACK_THEN_TRANSITION(0, I2C_WRITE)
    I2C_NACK: `ACK_THEN_TRANSITION(1, I2C_IDLE)
  endcase

  if (i2c_stop) begin
    i2c_address_valid <= 0;
    i2c_state <= I2C_IDLE;
  end else if (i2c_start) begin
    i2c_state <= I2C_START;
  end
end

endmodule
