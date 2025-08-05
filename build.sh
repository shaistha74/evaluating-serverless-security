#!/bin/bash
set -e

cd benign_lambda && zip ../benign_lambda.zip index.py && cd ..
cd malicious_permission && zip ../malicious_permission.zip index.py && cd ..
cd malicious_leakage && zip ../malicious_leakage.zip index.py && cd ..
cd malicious_dow && zip ../malicious_dow.zip index.py && cd ..

echo "✅ All Lambda packages built successfully"
