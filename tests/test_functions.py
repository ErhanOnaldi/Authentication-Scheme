import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import time
import threading
import hashlib
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import core.fuzzyextractor as fuzzyextractor
from core.entities import SmartDevice, TrustedAuthority
from core.utils import scalar_mult

# Function to calculate the average time
def calculate_average(times):
    return sum(times) / len(times)

# Hash Function Test
def hash_function_test(input_data):
    start_time = time.time()
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(input_data)
    digest.finalize()
    elapsed_time = time.time() - start_time
    return elapsed_time

# Gen Function Test
def gen_function_test(BIOi):
    start_time = time.time()
    extractor = fuzzyextractor.FuzzyExtractor(16, 8)
    _, helper = extractor.generate(np.frombuffer(BIOi, dtype=np.uint8))
    elapsed_time = time.time() - start_time
    return elapsed_time, helper

# Rep Function Test
def rep_function_test(BIOi, helper):
    start_time = time.time()
    extractor = fuzzyextractor.FuzzyExtractor(16, 8)
    extractor.reproduce(np.frombuffer(BIOi, dtype=np.uint8), helper)
    elapsed_time = time.time() - start_time
    return elapsed_time

# Point Multiplication Test
def point_multiply_test(public_key, scalar):
    start_time = time.time()
    scalar_mult(scalar, public_key, public_key.curve)
    elapsed_time = time.time() - start_time
    return elapsed_time

# Trusted Authority Hash Function Test
def ta_hash_function_test(ta, data):
    start_time = time.time()
    ta.h0(data)
    elapsed_time = time.time() - start_time
    return elapsed_time

# Trusted Authority Polynomial Generation Test
def ta_generate_polynomial_test(ta, degree):
    start_time = time.time()
    ta._generate_polynomial(degree)
    elapsed_time = time.time() - start_time
    return elapsed_time

# Function to run the tests multiple times and collect execution times
def run_tests(functions, inputs, iterations=40):
    results = {func.__name__: [] for func in functions}

    for _ in range(iterations):
        for func, args in zip(functions, inputs):
            elapsed_time = func(*args)
            if isinstance(elapsed_time, tuple):  # If the function returns a tuple
                elapsed_time = elapsed_time[0]  # Use only the elapsed time
            results[func.__name__].append(elapsed_time)

    return results

# Main function
if __name__ == "__main__":
    # Example Inputs
    example_hash_inputs = [b"test" * 100000]
    example_bio_data = b'\x00' * 16
    example_scalar = 123345795456 * 32094098574377829585
    trusted_authority = TrustedAuthority()
    public_key = trusted_authority.public_key

    # First run Gen function to get helper data
    gen_time, helper = gen_function_test(example_bio_data)

    # List of functions and their inputs
    functions_to_test = [
        hash_function_test,
        rep_function_test,
        point_multiply_test,
        ta_generate_polynomial_test,
    ]

    inputs_for_functions = [
        (example_hash_inputs[0],),
        (example_bio_data, helper),
        (public_key, example_scalar),
        (trusted_authority, 3)
    ]

    # Run tests and collect execution times
    execution_times = run_tests(functions_to_test, inputs_for_functions)

    # Print out the average execution time for each function
    for func_name, times in execution_times.items():
        average_time = calculate_average(times)
        print(f"Average time for {func_name}: {average_time:.6f} seconds")

    # Also print Gen function time
    print(f"Gen function time: {gen_time:.6f} seconds")
