#!/bin/bash

# Script to run ./tests.sh multiple times and count ThreadSanitizer occurrences
# Usage: ./run_tests_multiple.sh [N] where N is the number of times to run (default: 10)

# Number of times to run the test (default to 10 if not provided)
N=${1:-10}

echo "Running tests $N times..."
echo "Command: ./tests.sh -VV -L partitions -C partitions"
echo "----------------------------------------"

# Counter for files containing ThreadSanitizer
tsan_count=0

# Run the test N times
for i in $(seq 1 $N); do
    echo "Run $i/$N..."
    
    # Run the test and capture output (ignore exit code)
    ./tests.sh -VV -L partitions -C partitions > "out${i}.txt" 2>&1 || true
    
    # Check if this output file contains "ThreadSanitizer"
    if grep -q "ThreadSanitizer" "out${i}.txt" 2>/dev/null; then
        echo "  -> out${i}.txt contains ThreadSanitizer"
        ((tsan_count++))
    else
        echo "  -> out${i}.txt does not contain ThreadSanitizer"
    fi
done

echo "----------------------------------------"
echo "Summary:"
echo "Total runs: $N"
echo "Files containing 'ThreadSanitizer': $tsan_count"
echo "Files without 'ThreadSanitizer': $((N - tsan_count))"

if [ $tsan_count -gt 0 ]; then
    echo ""
    echo "Files with ThreadSanitizer issues:"
    for i in $(seq 1 $N); do
        if grep -q "ThreadSanitizer" "out${i}.txt" 2>/dev/null; then
            echo "  - out${i}.txt"
        fi
    done
fi
