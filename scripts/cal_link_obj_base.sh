#!/bin/bash

#
# Author: MingyuanLuo <myluo24@m.fudan.edu.cn>
# Slightly modified by Qiang Liu <cyruscyliu@gmail.com>
#

# Path to your text file
file=$SNAPSHOT_BASE/layout

# Use grep to find the line with "qemu-system-x86_64"
line=$(grep "qemu-system-x86_64" "$file" | head -1)

# Extract the start address, sh_addr, and compute the base address
if [[ -n "$line" ]]; then
        # Extract the start address (first hex value after "Range:")
        start_address=$(echo "$line" | awk '{print $3}' | sed 's/-//' | tr '[:lower:]' '[:upper:]')

        # Extract the sh_addr (last hex value in the line)
        sh_addr=$(echo "$line" | awk '{print $NF}' | tr '[:lower:]' '[:upper:]')

        # Convert both values to decimal, subtract, and convert back to hexadecimal
        LINK_OBJ_BASE=0x$(echo "obase=16; ibase=16; $start_address - $sh_addr" | bc | tr '[:upper:]' '[:lower:]')

        # Output the result
        echo "LINK_OBJ_BASE=$LINK_OBJ_BASE"
else
        echo "No line found for qemu-system-x86_64"
fi
