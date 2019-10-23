#!/bin/bash
set -e

# Run Infer on both our C and Java code
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 .
infer run --compilation-database compile_commands.json
infer run -- mvn clean compile

# Clean up the CMake generated file
rm compile_commands.json
