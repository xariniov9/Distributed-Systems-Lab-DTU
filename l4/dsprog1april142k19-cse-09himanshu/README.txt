# Compiling the program

1. Open terminal in the directory and run command:

gcc dsprog1april142k19-cse-09himanshu.c

# Executing the program

1. Open 6 terminal windows after the compilation of the above C program and run the following commands:

./a.out <id>

2. id is a command line argument specifying the process id for each process. It ranges from 1 to 6 for current input for each terminal respectively.

# Input

1. All the terminals take input from a common text file with name "input.txt" in the same working directory. Its specification is provided below.

2. The example input is specified in the input.txt file. First 'n' lines have comma separated integers. First integer specifies the port id, second integer represents the port number for this process and remaining numbers represent the neighbours.

3. Last integer represents the port id which will initiate the election algorithm.
