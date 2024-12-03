# BSC project - Marcos Tomaszewski

## Prerequisites

- Java 17 or higher

## Setup

1. Clone the repository:
    ```sh
    git clone https://github.com/Seis/bsc_dev
    cd bsc_dev
    ```

2. Replace the values of `.env` file in the test directory of the project as needed, the existing values should work tho.

    ```plaintext
      MESSAGE=<message to sign in cms>
      SIG_ALG=<signature algorithm>
      RESIGN_COUNT=<signature count>
      DEBUG_LEVEL=ALL
      XML=<XML to sign>

      CERT_1_PATH=<Path to nth certificate>
      CERT_1_PEM=<Path to nth certificate PEM>
      CERT_N_PASS=<password to the nth certificate>

      CERT_1_PATH=<Path to first certificate>
      CERT_1_PEM=<Path to first certificate PEM>
      CERT_1_PASS=<password to the first certificate>
    ```

    Replace the placeholders with the actual values for your environment.

## Building the Project

To build the project, run the following command:

```sh
mvn clean install
```

## Running Tests

To run the tests, use the following command:

```sh
mvn test
```

## Usage

### Signing and Verifying

The classes `TestXML` and `TestCMS` in `src/test/java/sign/*` both contains a test method `signAndVerify` that demonstrates how to sign and verify an XML/CMS document using the provided environment variables.