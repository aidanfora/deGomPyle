# deGomPyle

`deGomPyle` is a collection of Python scripts that are designed to enhance decompilation analysis of Go binaries. They can be easily imported into the Ghidra Script Manager to streamline the reverse engineering process.


### Key Features
- **Function Name Restoration**: Automatically restores function names in stripped Go binaries, making the code easier to navigate and understand.
- **String Splitting**: Splits long sequences of concatenated strings, facilitating easier reading and searching of specific strings within the binary.

Additionally, the repository includes a Proof-Of-Concept script designed for binary obfuscation, which works by locating and removing the stored function name metadata within Go binaries.

### Usage

1. Clone the Repository:
    ```sh
    git clone https://github.com/aidanfora/deGomPyle.git
    ```

2. Copy the set of scripts into your `ghidra_scripts` folder.

3. Run the script from the Ghidra Script Manager

#### Using the Obfuscation Script

Compile a Go binary and include its absolute path in the `modify_gopclntab` function at the end of the script.


### Demonstration

This demonstrates the recovery of lost function names from a basic "Hello World" program written in Go.

https://github.com/aidanfora/deGomPyle/assets/122984737/f15a7bbd-b66d-48c1-a0a6-2d15334609b2
