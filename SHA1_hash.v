module SHA1_hash(
		input          clk,
		input          nreset,          // Initializes the SHA1_hash module
		input          start_hash,      // Tells SHA1_hash to start hashing the given frame
		input  [31:0]  message_addr,    // Starting address of the messagetext frame
		                                // i.e., specifies from where SHA1_hash must read the messagetext frame
		input  [31:0]  message_size,    // Length of the message in bytes
		output [159:0] hash,            // hash results
		output         done,            // done is a signal to indicate that hash is complete
		output         port_A_clk,      // clock to dpsram (drive this with the input clk)
		output [31:0]  port_A_data_in,  // write data to the dpsram (ciphertext)
		input  [31:0]  port_A_data_out, // read data from the dpsram (messagetext)
		output [15:0]  port_A_addr,     // address of dpsram being read/written
		output         port_A_we        // read/write selector for dpsram
);
	// Finite-state machine
	parameter IDLE  = 3'b000;
	parameter READ1 = 3'b001;
	parameter READ2 = 3'b010;
	parameter PAD   = 3'b011;
	parameter HASH  = 3'b100;
	parameter DONE  = 3'b101;
	
	reg [2:0] state;
	
	// SHA-1
	reg [31:0] h0, h1, h2, h3, h4;
	reg [31:0] a, b, c, d, e;
	reg [31:0] w [0:79];
	reg [6:0] t;
	reg done_reg;
	
	wire [31:0]    f = (t < 20) ? ((b & c) | ((b ^ 32'hFFFFFFFF) & d))
	                 : (t < 40) ? (b ^ c ^ d)
			           : (t < 60) ? ((b & c) | (b & d) | (c & d))
			           :            (b ^ c ^ d);
	wire [31:0]    k = (t < 20) ? 32'h5A827999
	                 : (t < 40) ? 32'h6ED9EBA1
			           : (t < 60) ? 32'h8F1BBCDC
			           :            32'hCA62C1D6;
	wire [31:0] T    = rotl(a, 5) + f + w[t] + k + e;
	wire [31:0] size_in_bits = message_size << 3;
	
	assign hash = {h0, h1, h2, h3, h4};
	assign done = done_reg;
	
	// DPSRAM
	reg [15:0] read_addr;
	
	integer i;
	
	assign port_A_clk = clk;
	assign port_A_addr = read_addr;
	assign port_A_we = 0;
	
	reg [6:0]  buffer_size;
	reg [7:0]  buffer [0:63];
	reg [31:0] bytes_read;
	reg pad_one;
	
	wire [2:0] last_byte_size = (message_size % 4 == 0) ? 4 : message_size % 4;

	always @(posedge clk or negedge nreset) begin
		if (!nreset) begin
			state <= IDLE;
		
			h0 <= 32'h00000000;
			h1 <= 32'h00000000;
			h2 <= 32'h00000000;
			h3 <= 32'h00000000;
			h4 <= 32'h00000000;
		   a  <= 32'h00000000;
			b  <= 32'h00000000;
			c  <= 32'h00000000;
			d  <= 32'h00000000;
			e  <= 32'h00000000;
			
			for (i = 0; i < 80; i = i + 1) begin
				w[i] <= 32'h00000000;
			end
			
			t        <= 7'b0000000;
			done_reg <= 1'b0;
			
			read_addr  <= 16'h0000;
			bytes_read <= 32'h00000000;
			pad_one    <= 0;
			clearBuffer();
			
			state <= IDLE;
		end else begin
			case (state)
				IDLE: begin
					$display("[IDLE]");
					if (start_hash) begin
						read_addr <= message_addr[15:0];

						h0 <= 32'h67452301;
						h1 <= 32'hEFCDAB89;
						h2 <= 32'h98BADCFE;
						h3 <= 32'h10325476;
						h4 <= 32'hC3D2E1F0;
						
						state <= READ1;
					end
				end
				READ1: begin
					$display("[READ1] Getting value at 0x%x", read_addr);
					read_addr <= read_addr + 4;
					state <= (message_size == 0) ? HASH : READ2;
				end
				READ2: begin
					$display("[READ2] Value at 0x%x: %x %x %x %x",
					         read_addr - 4,
					         port_A_data_out[7:0],
								port_A_data_out[15:8],
								port_A_data_out[23:16],
								port_A_data_out[31:24]);

					buffer[buffer_size]     <= port_A_data_out[7:0];
					buffer[buffer_size + 1] <= port_A_data_out[15:8];
					buffer[buffer_size + 2] <= port_A_data_out[23:16];
					buffer[buffer_size + 3] <= port_A_data_out[31:24];
					a <= h0;
					b <= h1;
					c <= h2;
					d <= h3;
					e <= h4;
					w[0] <= {buffer[0], buffer[1], buffer[2], buffer[3]};

					// NOTE: This if block may decrease Fmax.
					if (bytes_read + 4 < message_size) begin
						$display("[READ2] Bytes read: %d", bytes_read + 4);
						bytes_read  <= bytes_read + 4;
						buffer_size <= buffer_size + 4;

						if (buffer_size + 4 < 64) begin
							// Not end of message. Buffer is not full. Keep reading.
							$display("[READ2] Getting value at 0x%x", read_addr);
							read_addr <= read_addr + 4;
						end else begin
							// Not end of message. Buffer is full. Process chunk.
							state <= HASH;
						end
					end else begin
						$display("[READ2] Bytes read: %d", bytes_read + last_byte_size);
						bytes_read  <= bytes_read + last_byte_size;
						buffer_size <= buffer_size + last_byte_size;

						if (buffer_size + last_byte_size + 1 + 8 <= 64) begin
							$display("[READ2] End of message. Buffer is big enough for padding and message length.");
							buffer[buffer_size + last_byte_size] <= 8'h80;
							buffer[60] <= size_in_bits[7:0];
							buffer[61] <= size_in_bits[15:8];
							buffer[62] <= size_in_bits[23:16];
							buffer[63] <= size_in_bits[31:24];
							state <= HASH;
						end else if (buffer_size + last_byte_size + 1 <= 64) begin
							$display("[READ2] End of message. Buffer is big enough for padding, but not message length. Need extra chunk.");
							buffer[buffer_size + last_byte_size] <= 8'h80;
							pad_one <= 0;
							state <= HASH;
						end else begin
							$display("End of message. Buffer is not big enough for padding and message length. Need extra chunk.");
							pad_one <= 1;
							state <= HASH;
						end
					end
				end
				PAD: begin
					$display("[PAD]");
					if (pad_one) begin
						buffer[0] <= 8'h80;
						w[0]      <= 32'h80000000;
					end else begin
						buffer[0] <= 8'h00;
						w[0]      <= 32'h00000000;
					end
					buffer[60] <= size_in_bits[31:24];
					buffer[61] <= size_in_bits[23:16];
					buffer[62] <= size_in_bits[15:8];
					buffer[63] <= size_in_bits[7:0];
					a <= h0;
					b <= h1;
					c <= h2;
					d <= h3;
					e <= h4;
					state <= HASH;
				end
				HASH: begin
					$display("[HASH] t: %d, w[t]: %x, A: %x, B: %x, C: %x, D: %x, E: %x, F: %x, K: %x", t, w[t], a, b, c, d, e, f, k);
					displayBuffer();
					
					t <= (t + 1) % 80;
					
					if ((t+1) < 16) begin
						w[t+1] <= {buffer[(t+1) * 4], buffer[(t+1) * 4 + 1], buffer[(t+1) * 4 + 2], buffer[(t+1) * 4 + 3]};
					end else begin
						w[t+1] <= rotl(w[(t+1)-3] ^ w[(t+1)-8] ^ w[(t+1)-14] ^ w[(t+1)-16], 1);
					end
					
					a <= T;
					b <= a;
					c <= rotl(b, 30);
					d <= c;
					e <= d;
					
					if (t == 79) begin
						h0 <= h0 + T;
						h1 <= h1 + a;
						h2 <= h2 + rotl(b, 30);
						h3 <= h3 + c;
						h4 <= h4 + d;
						state <= (bytes_read < message_size)                 ? READ1
						       : (buffer_size + last_byte_size + 1 + 8 > 64) ? PAD
								 :                                               DONE;
						clearBuffer();
					end
				end
				DONE: begin
					done_reg <= 1;
				end
			endcase
		end
	end
	
	function [31:0] toBigEndian;
		input [31:0] value;
		toBigEndian = {value[7:0], value[15:8], value[23:16], value[31:24]};
	endfunction
	
	function [31:0] rotl;
		input [31:0] value;
		input [7:0] shift;
		rotl = (value << shift) | (value >> (32 - shift));
	endfunction
	
	task clearBuffer;
		begin
			buffer_size <= 7'b0000000;
			
			for (i = 0; i < 64; i = i + 1) begin
				buffer[i] <= 8'h00;
			end
		end
	endtask
	
	task displayBuffer;
		begin
			$display("buffer size: %d", buffer_size);
			for (i = 0; i < 4; i = i + 1) begin
				$display("buffer: %x %x %x %x  %x %x %x %x  %x %x %x %x  %x %x %x %x",
							buffer[i * 16 + 0],  buffer[i * 16 + 1],  buffer[i * 16 + 2],  buffer[i * 16 + 3],
							buffer[i * 16 + 4],  buffer[i * 16 + 5],  buffer[i * 16 + 6],  buffer[i * 16 + 7],
							buffer[i * 16 + 8],  buffer[i * 16 + 9],  buffer[i * 16 + 10], buffer[i * 16 + 11],
							buffer[i * 16 + 12], buffer[i * 16 + 13], buffer[i * 16 + 14], buffer[i * 16 + 15]);
			end
		end
	endtask
endmodule
