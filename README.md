# CPace-Ristretto255 Attack Simulation

A CPace implementation with a simulated discrete logarithm attack for educational purposes.

This project demonstrates a theoretical vulnerability in CPace when facing quantum computing attacks.

## Description

[CPace](https://github.com/jedisct1/rust-cpace) is a protocol for two parties that share a low-entropy secret (password) to derive a strong shared key without disclosing the secret to offline dictionary attacks.

This implementation includes:

- A complete CPace implementation using Ristretto255 and SHA-512
- A simulated discrete logarithm (DLOG) oracle attack
- Performance analysis tools to measure attack effectiveness

**Educational Purpose Only**: This project is for cryptographic research and education. The attack simulation assumes access to a quantum computer capable of solving discrete logarithm problems.

## Attack Overview

The simulated attack works by:

1. Passively observing CPace Step 1 packets on the network
2. Using a simulated DLOG oracle to test password candidates
3. Performing an exhaustive search over the password space
4. Measuring the average number of oracle queries required

## Usage

### Running the Attack Simulation

```bash
cargo run --release <password_length> <iterations>
```

**Parameters:**

- `password_length`: Length of the random password to generate and attack (1-10 recommended)
- `iterations`: Number of simulation runs to average results

**Example:**

```bash
# Simulate attack on 3-character passwords, run 5 times
cargo run --release 3 5
```

### Sample Output

```
Simulation de l'attaque DLOG sur CPace avec un mot de passe de longueur 3 (5 iterations)...
----- Observation passive et attaque DLOG -----
Mot de passe généré : 'aB7'
Nombre total de mots de passe à tester : 238328 (238.3 milliers)
Packet intercepté : '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p...'
...
Simulation terminée avec succès, nombre de requêtes à l'oracle : 119164

-------- Résultats de la simulation -----------
Nombre moyen de requêtes à l'oracle : 119164.00
```

### CPace Protocol Usage

The project also includes a complete CPace implementation from the GitHub repository [rust-cpace
](https://github.com/jedisct1/rust-cpace):

```rust
use crate::cpace::CPace;

// Client initiates Step 1
let client = CPace::step1("password", "client", "server", Some("ad")).unwrap();

// Server responds with Step 2
let step2 = CPace::step2(&client.packet(), "password", "client", "server", Some("ad")).unwrap();

// Client completes Step 3
let shared_keys = client.step3(&step2.packet()).unwrap();

// Both parties now have the same shared keys
assert_eq!(shared_keys.k1, step2.shared_keys().k1);
assert_eq!(shared_keys.k2, step2.shared_keys().k2);
```

## Project Structure

- [`src/cpace.rs`](src/cpace.rs) - Complete CPace protocol implementation
- [`src/attack.rs`](src/attack.rs) - DLOG oracle attack simulation
- [`src/main.rs`](src/main.rs) - Command-line interface and simulation runner

## Technical Details

- **Elliptic Curve**: Ristretto255 (built on Curve25519)
- **Hash Function**: SHA-512
- **Password Character Set**: `[a-zA-Z0-9]` (62 characters)
- **Attack Method**: Exhaustive search with simulated DLOG oracle
- **Parallelization**: Uses Rayon for multi-threaded password testing

## Limitations

- The DLOG oracle is simulated and assumes quantum computing capabilities
- Password search is exhaustive - real attacks might use dictionary approaches
- Performance depends on password length (exponential complexity)
- Maximum recommended password length: 10 characters for reasonable execution time

## Security Analysis

This simulation demonstrates that CPace's security relies on the hardness of the discrete logarithm problem. In a post-quantum world where DLOG can be efficiently solved, password-based protocols like CPace become vulnerable to passive attacks.

**Average Oracle Queries**: For a password of length `n` with character set size `c`, the expected number of queries is `c^n / 2`.

## Dependencies

- `curve25519-dalek` - Elliptic curve operations
- `hmac-sha512` - Hash functions
- `rayon` - Parallel computation
- `rand` - Random number generation
- `difference` - Visual diff display

## Building

```bash
cargo build --release
```

For optimal performance, always use the `--release` flag when running simulations.
