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
	// FSM
	parameter IDLE  = 3'b000;
	parameter READ1 = 3'b001;
	parameter READ2 = 3'b010;
	parameter PAD   = 3'b011;
	parameter HASH  = 3'b100;
	parameter DONE  = 3'b101;
	
	reg [2:0] state;
	reg [2:0] state_n;
	reg       state_wen;
	
	reg done_reg;
	reg done_n;
	reg done_wen;
	
	assign done = done_reg;
	
	// Buffer and DPSRAM
	reg [15:0] read_addr;
	reg [15:0] read_addr_n;
	reg        read_addr_wen;
	
	reg [31:0] bytes_read;
	reg [31:0] bytes_read_n;
	reg        bytes_read_wen;
	
	integer    i;
	
	reg [7:0]  buffer [0:63];
	
	reg [6:0]  buffer_size;
	reg [6:0]  buffer_size_n;
	reg        buffer_size_wen;
	
	wire [2:0] last_byte_size = (message_size % 4 == 0) ? 4 : message_size % 4;
	
	reg pad_one;
	
	assign port_A_clk  = clk;
	assign port_A_addr = read_addr;
	assign port_A_we   = 0;
	
	// SHA-1
	reg [31:0] h0, h1, h2, h3, h4;
	reg [31:0] h0_n, h1_n, h2_n, h3_n, h4_n;
	reg        h_wen;
	
	reg [31:0] a, b, c, d, e;
	reg [31:0] a_n, b_n, c_n, d_n, e_n;
	reg        ae_wen;
	
	reg [32:0] f;
	reg [32:0] k;
	
	reg [31:0] w [0:79];
	
	reg [6:0]  t;
	reg [6:0]  t_n;
	reg [6:0]  t_wen;
	
	wire [31:0] a5  = {a[26:0], a[31:27]};
	wire [31:0] b30 = {b[1:0], b[31:2]};
	wire [31:0] T   = a5 + f + w[t] + k + e;
	wire [31:0] size_in_bits = message_size << 3;
	wire        finish_chunk = (t == 79);
	
	assign hash = {h0, h1, h2, h3, h4};
	
	initial begin
		for (i = 0; i < 80; i = i + 1) begin
			w[i] = 32'h00000000;
		end
	end
	
	always @(posedge clk or negedge nreset) begin
		if (!nreset) begin
			state    <= IDLE;
			done_reg <= 0;
			
			read_addr  <= 16'h0000;
			bytes_read <= 32'h00000000;
			
			buffer_size <= 7'b0000000;
		
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
		end else begin
			case (state)
				IDLE: begin
					if (start_hash) begin
						clearBuffer();
					end
				end
				READ2: begin
					buffer[buffer_size]     <= port_A_data_out[7:0];
					buffer[buffer_size + 1] <= port_A_data_out[15:8];
					buffer[buffer_size + 2] <= port_A_data_out[23:16];
					buffer[buffer_size + 3] <= port_A_data_out[31:24];
					
					if (!(bytes_read + 4 < message_size)) begin
						if (buffer_size + last_byte_size + 1 + 8 <= 64) begin
							$display("[READ2] End of message. Buffer is big enough for padding and message length.");
							buffer[buffer_size + last_byte_size] <= 8'h80;
							buffer[60] <= size_in_bits[7:0];
							buffer[61] <= size_in_bits[15:8];
							buffer[62] <= size_in_bits[23:16];
							buffer[63] <= size_in_bits[31:24];
						end else if (buffer_size + last_byte_size + 1 <= 64) begin
							$display("[READ2] End of message. Buffer is big enough for padding, but not message length. Need extra chunk.");
							buffer[buffer_size + last_byte_size] <= 8'h80;
							pad_one <= 0;
						end else begin
							$display("End of message. Buffer is not big enough for padding and message length. Need extra chunk.");
							pad_one <= 1;
						end
					end
				end
				PAD: begin
					if (pad_one) begin
						buffer[0] <= 8'h80;
					end else begin
						buffer[0] <= 8'h00;
					end
					
					buffer[60] <= size_in_bits[31:24];
					buffer[61] <= size_in_bits[23:16];
					buffer[62] <= size_in_bits[15:8];
					buffer[63] <= size_in_bits[7:0];
				end
				HASH: begin
					if (finish_chunk) begin
						clearBuffer();
					end
				end
			endcase
			
			if (state_wen) begin
				state <= state_n;
			end
			
			if (done_wen) begin
				done_reg <= done_n;
			end
			
			if (read_addr_wen) begin
				read_addr <= read_addr_n;
			end
			
			if (bytes_read_wen) begin
				bytes_read <= bytes_read_n;
			end
			
			if (buffer_size_wen) begin
				buffer_size <= buffer_size_n;
			end

			if (h_wen) begin
				h0 <= h0_n;
				h1 <= h1_n;
				h2 <= h2_n;
				h3 <= h3_n;
				h4 <= h4_n;
			end
			
			if (ae_wen) begin
				a <= a_n;
				b <= b_n;
				c <= c_n;
				d <= d_n;
				e <= e_n;
			end
			
			if (t_wen) begin
				t <= t_n;
			end
		end
	end
	
	// FSM
	always @(*) begin
		state_n   = IDLE;
		state_wen = 0;
		done_n    = 0;
		done_wen  = 0;

		case (state)
			IDLE: begin
				if (start_hash) begin
					state_n   = READ1;
					state_wen = 1;
				end
			end
			READ1: begin
				state_n   = READ2;
				state_wen = 1;
			end
			READ2: begin
				$display("bytes_read: %d, message_size: %d, %d, %d", bytes_read, message_size, (bytes_read + 4 < message_size), !((bytes_read + 4 < message_size) && (buffer_size + 4 < 64)));
				if (!((bytes_read + 4 < message_size) && (buffer_size + 4 < 64))) begin
					state_n   = HASH;
					state_wen = 1;
				end
			end
			PAD: begin
				state_n   = HASH;
				state_wen = 1;
			end
			HASH: begin
				if (finish_chunk) begin
					if (bytes_read < message_size) begin
						state_n = READ1;
					end else if (buffer_size + last_byte_size + 1 + 8 > 64) begin
						state_n = PAD;
					end else begin
						state_n = DONE;
					end
					
					state_wen = 1;
				end
			end
			DONE: begin
				state_n   = IDLE;
				state_wen = 1;
				done_n    = 1;
				done_wen  = 1;
			end
		endcase
	end
	
	// Read address
	always @(*) begin
		read_addr_n     = 16'h0000;
		read_addr_wen   = 0;
		
		case (state)
			IDLE: begin
				if (start_hash) begin
					read_addr_n   = message_addr[15:0];
					read_addr_wen = 1;
				end
			end
			READ1: begin
				read_addr_n   = read_addr + 4;
				read_addr_wen = 1;
			end
			READ2: begin
				if ((bytes_read + 4 < message_size) && (buffer_size + 4 < 64)) begin
					read_addr_n   = read_addr + 4;
					read_addr_wen = 1;
				end
			end
		endcase
	end
	
	// Buffer and DPSRAM
	always @(*) begin
		bytes_read_n    = 32'h00000000;
		bytes_read_wen  = 0;
		buffer_size_n   = 7'b0000000;
		buffer_size_wen = 0;
		
		case (state)
			IDLE: begin
				if (start_hash) begin
					bytes_read_n    = 32'h00000000;
					bytes_read_wen  = 1;
					buffer_size_n   = 7'b0000000;
					buffer_size_wen = 1;
				end
			end
			READ2: begin
				if (bytes_read + 4 < message_size) begin
					bytes_read_n    = bytes_read + 4;
					bytes_read_wen  = 1;
					buffer_size_n   = buffer_size + 4;
					buffer_size_wen = 1;
				end else begin
					bytes_read_n    = bytes_read + last_byte_size;
					bytes_read_wen  = 1;
					buffer_size_n   = buffer_size + last_byte_size;
					buffer_size_wen = 1;
				end
			end
			HASH: begin
				if (finish_chunk) begin
					buffer_size_n   = 7'b0000000;
					buffer_size_wen = 1;
				end
			end
		endcase
	end
	
	// SHA-1 computation: H
	always @(*) begin
		h0_n  = 32'h00000000;
		h1_n  = 32'h00000000;
		h2_n  = 32'h00000000;
		h3_n  = 32'h00000000;
		h4_n  = 32'h00000000;
		h_wen = 0;

		case (state)
			IDLE: begin
				if (start_hash) begin
					h0_n  = 32'h67452301;
					h1_n  = 32'hEFCDAB89;
					h2_n  = 32'h98BADCFE;
					h3_n  = 32'h10325476;
					h4_n  = 32'hC3D2E1F0;
					h_wen = 1;
				end
			end
			HASH: begin
				if (finish_chunk) begin
					h0_n  = h0 + T;
					h1_n  = h1 + a;
					h2_n  = h2 + b30;
					h3_n  = h3 + c;
					h4_n  = h4 + d;
					h_wen = 1;
				end
			end
		endcase
	end
	
	// SHA-1 computation: A-E
	always @(*) begin
		a_n    = 32'h00000000;
		b_n    = 32'h00000000;
		c_n    = 32'h00000000;
		d_n    = 32'h00000000;
		e_n    = 32'h00000000;
		ae_wen = 0;
		
		case (state)
			READ2: begin
				a_n    = h0;
				b_n    = h1;
				c_n    = h2;
				d_n    = h3;
				e_n    = h4;
				ae_wen = 1;
			end
			HASH: begin
				if (t < 16) begin
					w[t] = {buffer[t * 4], buffer[t * 4 + 1], buffer[t * 4 + 2], buffer[t * 4 + 3]};
				end else begin
					w[t] = rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
				end
				
				if (t < 20) begin
					f = (b & c) | ((~b) & d);
					k = 32'h5A827999;
				end else if (t < 40) begin
					f = b ^ c ^ d;
					k = 32'h6ED9EBA1;
				end else if (t < 60) begin
					f = (b & c) | (b & d) | (c & d);
					k = 32'h8F1BBCDC;
				end else begin
					f = b ^ c ^ d;
					k = 32'hCA62C1D6;
				end
				
				a_n    = T;
				b_n    = a;
				c_n    = b30;
				d_n    = c;
				e_n    = d;
				ae_wen = 1;
			end
			PAD: begin
				if (pad_one) begin
					w[0] <= 32'h80000000;
				end else begin
					w[0] <= 32'h00000000;
				end
				
				a_n    = h0;
				b_n    = h1;
				c_n    = h2;
				d_n    = h3;
				e_n    = h4;
				ae_wen = 1;
			end
		endcase
	end
	
	// SHA-1 computation: t
	always @(*) begin
		t_n   = 7'b0000000;
		t_wen = 0;
		
		case (state)
			READ2: begin
				t_n   = 7'b0000000;
				t_wen = 1;
			end
			HASH: begin
				if (t == 79) begin
					t_n = 0;
				end else begin
					t_n = t + 1;
				end
				
				t_wen = 1;
			end
		endcase
	end
	
	// Debug message
	always @(posedge clk) begin
		case (state)
			IDLE: begin
				$display("[IDLE]");
			end
			READ1: begin
				$display("[READ1] Getting value at 0x%x", read_addr);
			end
			READ2: begin
				$display("[READ2] Value at 0x%x: %x %x %x %x",
				         read_addr - 4,
							port_A_data_out[7:0],
							port_A_data_out[15:8],
							port_A_data_out[23:16],
							port_A_data_out[31:24]);
				if ((bytes_read + 4 < message_size) && (buffer_size + 4 < 64)) begin
					$display("[READ2] Getting value at 0x%x", read_addr);
				end
				displayBuffer();
			end
			HASH: begin
				$display("[HASH] t: %d, w[t]: %x, A: %x,  B: %x,  C: %x,  D: %x,  E: %x, F:%x, K: %x", t, w[t], a, b, c, d, e, f, k);
			end
		endcase
	end
		
	function [31:0] rotl;
		input [31:0] value;
		input [7:0] shift;
		rotl = (value << shift) | (value >> (32 - shift));
	endfunction

	task clearBuffer;
		begin
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
