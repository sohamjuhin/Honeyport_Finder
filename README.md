# Honeyport_Finder
Honey port Detection Tool
To run the C code that performs packet capturing using libpcap, you'll need to follow these steps:

1. **Prepare your environment:**
   - Ensure you have a C compiler installed on your system (such as GCC for Linux or MinGW for Windows).
   - Install libpcap development libraries. The package might be named `libpcap-dev` on Linux systems.

2. **Compile the C code:**
   - Save the C code into a file, for example, `packet_sniffer.c`.
   - Open a terminal or command prompt.
   - Compile the code using a C compiler. For example, using GCC, you might run:
     ```
     gcc -o packet_sniffer packet_sniffer.c -lpcap
     ```
     This command compiles the code and links it with the libpcap library.

3. **Run the compiled program:**
   - Execute the compiled program by running:
     ```
     ./packet_sniffer
     ```
   - Ensure you have the necessary permissions to capture packets (typically, this requires root or elevated privileges).

Remember to replace `"eth0"` in the code with the appropriate network interface you want to sniff on (it could be `eth0`, `en0`, or similar depending on your system).

Be cautious when working with packet capturing as it involves interacting with the network interface at a low level. Additionally, ensure that your actions comply with legal regulations and you have the necessary permissions to capture network traffic.
