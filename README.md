Authentication Scheme Implementation with SSO and Key Exchange
This project implements an authentication scheme using key exchange protocols and biometric data based on the mathematical operations provided in the relevant research paper. The project also integrates Single Sign-On (SSO) functionality using cryptographic primitives, elliptic curve operations, and a fuzzy extractor to handle biometric inputs.

Project Structure
authentication_scheme/
│
├── src/
│   ├── core/
│   │   ├── fuzzyextractor.py        # Fuzzy extractor for biometric data
│   │   ├── entities.py              # SmartDevice, FogServer, CloudServer, TrustedAuthority entities
│   │   └── utils.py                 # Utility functions for cryptographic operations (e.g., point multiplication)
│   ├── pre_deployment.py            # Pre-deployment phase for initializing trusted authority and entities
│   ├── key_exchange.py              # Key exchange process between devices, fog, and cloud servers
│   ├── user_registration.py         # User registration process
│   ├── login_authentication.py      # Login process for users with biometric data
│   ├── takebiodata.py               # Collect biometric data
│   └── main.py                      # Main script that integrates all phases
│
├── tests/
│   ├── test_functions.py            # Tests for key functions such as hash, Gen, Rep, and point multiplication
│   └── utils.test.py                # Test file for utility functions
│
└── requirements.txt                 # List of dependencies
Features
Pre-deployment phase: Sets up the Trusted Authority (TA), Smart Device, Fog Server, and Cloud Server.
Key exchange phase: Implements the secure exchange of keys between the Smart Device, Fog Server, and Cloud Server.
User registration phase: Handles user registration using biometrics and cryptographic primitives.
Login phase: Authenticates users based on previously registered biometric data.
Single Sign-On (SSO): Integrates SSO for seamless login across different services.

Prerequisites
To run this project, you’ll need Python 3.7+ and the following dependencies:
cryptography
numpy
sympy
opencv-python

You can install all required libraries using the requirements.txt file:
pip install -r requirements.txt
Setup

Clone the repository:
git clone https://github.com/your-username/Authentication-Scheme.git
cd Authentication-Scheme

Install dependencies:
pip install -r requirements.txt
Run the main script:

To run the full authentication process:
python src/main.py
Run tests:

Unit tests for functions like hashing, Gen, Rep, and point multiplication can be found in the tests folder. To run the tests:
python tests/test_functions.py

Usage
Pre-Deployment Phase
The pre_deployment.py script initializes the Trusted Authority (TA) and registers the Smart Device, Fog Server, and Cloud Server.

Key Exchange Phase
The key_exchange.py handles the secure key exchange between the devices using elliptic curve cryptography.

User Registration and Login
User Registration: In user_registration.py, the Smart Device collects user biometric data, generates the necessary cryptographic keys, and stores them securely using fuzzy extractors.
Login: The login_authentication.py script allows a user to log in by verifying the provided biometric data against the stored data using cryptographic verification.
SSO Integration
The SSO implementation allows users to log in once and use the same authentication session across different services. This is handled transparently in the login and registration phases.

Example
You can register a user by running the following command:
python src/user_registration.py

To simulate a login process:
python src/main.py
Testing Performance
We include a script to test the performance of critical cryptographic operations (test_functions.py). This script runs various functions multiple times and reports the average execution time.

Contribution
Contributions are welcome! Please open an issue or submit a pull request.

License
This project is licensed under the MIT License.

Acknowledgements
This project is based on the mathematical operations and research paper that proposes the authentication scheme. Special thanks to the original authors.
