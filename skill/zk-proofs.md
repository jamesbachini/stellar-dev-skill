# Zero-Knowledge Proofs on Stellar (Status-Sensitive)

## When to use this guide
Use this guide when the user asks for:
- On-chain ZK proof verification patterns
- Privacy-preserving smart contract architecture
- BN254/Poseidon readiness planning
- Groth16, UltraHonk, or PLONK integration strategy
- Cross-chain proof verification design
- Noir or Circom circuit development for Soroban
- RISC Zero zkVM integration with Stellar
- Commit-reveal schemes with ZK enforcement

This guide is intentionally status-aware. ZK capabilities on Stellar evolve with protocol and SDK releases.

Do not assume all capabilities are present on all networks/environments.

## Proving system landscape on Stellar

Three proving approaches are actively used by the Stellar developer community: Noir, Circom and RISC Zero

### Noir
A Rust-like domain specific programming language for creating zero-knowledge circuits. Note that Noir support is currently limited on Stellar due to processing constraints in a decentralized computing environment. This is a situation that we expect to see evolving throughout the course of the hackathon.
Noir Docs: https://noir-lang.org/docs/

#### Noir x Ultrahonk
The official backend for Noir generates Ultrahonk proofs. These are large proofs that use a lot of CPU to verify on-chain. The verifier contract below has  had some optimisations made to make this more feasible on Soroban.
Noir Ultranhonk Verifier: https://github.com/yugocabrio/rs-soroban-ultrahonk
Ultrahonk benefits from no trusted setup required (universal reference string via Aztec CRS).

#### Noir x Groth16
There is a Noir > Groth16 backend available: https://github.com/jamesbachini/Noir-Groth16
This uses BN254 host functions and generates a 256 byte proof.
Groth16 Verifier: https://github.com/jamesbachini/Noir-Groth16/blob/main/contracts/src/lib.rs
- Most common approach. Uses `soroban-sdk` BN254 host functions (`bn254().g1_mul`, `bn254().g1_add`, `bn254().pairing_check`).
- Proof size: 256 bytes (A: G1 64 bytes + B: G2 128 bytes + C: G1 64 bytes).
- Verification keys: alpha (G1: 64), beta (G2: 128), gamma (G2: 128), delta (G2: 128), IC points (G1: 64 each).
- Groth16 requires a per-circuit trusted setup (Powers of Tau ceremony + circuit-specific phase 2).

### Circom
Circom uses arithmetic based circuits which are compatible with snarkjs for generation of Groth16 proofs which can be verified on Stellar. 
- `snarkjs groth16 prove` outputs `{ proof, publicSignals }` + verification key.
- Proof can be verified locally via `snarkjs groth16 verify` before on-chain submission.
- JSON VK, proof, and public inputs converted to canonical hex byte arrays using crate circom-to-soroban-hex
Circom2 Groth16 Verifier: https://github.com/stellar/soroban-examples/tree/main/groth16_verifier
Writing Circom Circuits: https://docs.circom.io/getting-started/writing-circuits/

### RISC Zero
RISC Zero provides an execution environment where we can compute large amounts of data off-chain and then verify the output in a Stellar smart contract.
- General-purpose zkVM: write Rust guest programs, generate proofs of correct execution.
- Proof is a "seal" verified against an "image ID" (hash of the guest program).
- No circuit writing required; standard Rust code inside the guest.
- Well suited for complex game logic replay (physics simulations, multi-round games).
- Higher proof generation cost (minutes for complex computations) but simpler developer experience.
RISC Zero Docs: https://dev.risczero.com/
RISC Zero Verifier: https://github.com/NethermindEth/stellar-risc0-verifier/

## Architecture patterns

### 1) Verification gateway
Use a dedicated verifier contract (or module) for cryptographic checks:
- Normalize and validate inputs
- Enforce domain separation for statements
- Verify proof
- Emit explicit success/failure events

Benefits:
- Smaller audit surface
- Easier upgrades/migrations
- Cleaner operational telemetry

Proven pattern from hackathon projects: a standalone `ZkVerifier` contract that accepts circuit-specific verification keys, paired with game/application contracts that invoke it via cross-contract calls:

```rust
// Verifier client trait for cross-contract calls
#[contractclient(name = "VerifierClient")]
pub trait Verifier {
    fn verify(env: Env, circuit_id: u32, proof_bytes: Bytes, public_inputs: Bytes) -> bool;
}
```

### 2) Policy-and-proof split
Separate concerns:
- `Verifier`: cryptographic validity only
- `Policy`: business/risk/compliance logic
- `Application`: state transition after verifier + policy pass

Benefits:
- Better testability
- Safer upgrades
- Clearer incident response

### 3) Commit-reveal with ZK enforcement
The dominant pattern for hidden-information applications:
1. **Commit phase**: Player hashes private state with a salt using Poseidon, publishes commitment on-chain.
2. **Action phase**: Player generates a ZK proof that their action is consistent with the committed state.
3. **Verify phase**: Contract verifies proof against the stored commitment without learning private state.

This is used for hidden board games (Battleship, Stratego), private card hands (Poker), and sealed-bid mechanisms.

### 4) Feature flags and graceful fallback
Gate advanced paths by environment support:
- Enable ZK flows only where required primitives are verified available
- Keep deterministic fallback behavior for unsupported environments
- Document supported network/protocol matrix in deployment notes

A common pattern is mock mode: if no verification key is stored for a circuit, the verifier returns `true`, allowing development and testing without real proofs.

## Noir circuit patterns for Stellar

### Poseidon commitment (BN254)
The standard approach for committing hidden state:

```noir
use dep::poseidon::poseidon::bn254;

// Chain hash_2 calls to commit variable-length data
fn compute_commitment(salt: Field, values: [Field; N]) -> Field {
    let mut acc = bn254::hash_2([salt, values[0]]);
    for i in 1..N {
        acc = bn254::hash_2([acc, values[i]]);
    }
    acc
}
```

For fixed-size inputs, use `poseidon::bn254::hash_16` or similar:

```noir
use std::hash::poseidon;

let mut hash_inputs: [Field; 16] = [0; 16];
// ... populate inputs ...
let commitment = poseidon::bn254::hash_16(hash_inputs);
```

### Hidden-information proof (combat/action)
Prove a specific fact about committed state without revealing the rest:

```noir
fn main(
    // Private inputs
    salt: Field,
    positions: [Field; 10],
    ranks: [Field; 10],
    piece_index: u32,
    // Public inputs
    commitment: pub Field,
    combat_position: pub Field,
    revealed_rank: pub Field,
) {
    // 1. Verify commitment matches private board state
    let computed = compute_commitment(salt, positions, ranks);
    assert(computed == commitment, "Commitment mismatch");

    // 2. Verify the claimed fact about a specific piece
    assert(positions[piece_index] == combat_position);
    assert(ranks[piece_index] == revealed_rank);

    // 3. Validate domain constraints
    assert((revealed_rank as u32) >= 1);
    assert((revealed_rank as u32) <= 6);
}
```

### Board/state validation proof
Prove initial state satisfies game rules without revealing it:

```noir
fn main(
    ship_x: [Field; 5], ship_y: [Field; 5], ship_o: [Field; 5],
    salt: Field,
    board_hash: pub Field,
) {
    // 1. Validate each piece placement (bounds, no overlaps)
    let mut board: [[bool; 10]; 10] = [[false; 10]; 10];
    for i in 0..5 {
        // ... check bounds, mark occupied cells, assert no overlap ...
    }

    // 2. Verify Poseidon hash matches public commitment
    let computed_hash = poseidon::bn254::hash_16(hash_inputs);
    assert(computed_hash == board_hash);
}
```

### Shot/action verification proof
Prove an action outcome is correct given committed state:

```noir
fn main(
    // Private: defender's secret board
    ship_x: [Field; 5], ship_y: [Field; 5], ship_o: [Field; 5], salt: Field,
    // Public: known to both players
    board_hash: pub Field, shot_x: pub Field, shot_y: pub Field, hit: pub Field,
) {
    // 1. Verify board commitment
    assert(computed_hash == board_hash);
    // 2. Determine if shot hits any ship cell
    // 3. Assert claimed result matches actual result
    assert(hit == (is_hit as Field));
}
```

### MPC + ZK (coSNARKs)
For multi-party private computation (e.g., card shuffling where no single party should see all cards), combine MPC with ZK using TACEO coNoir.

## On-chain Poseidon hashing

For matching circuit commitments on-chain, two approaches:

### Using `soroban_poseidon` crate (Poseidon2)
```rust
use soroban_poseidon::poseidon2_hash;
use soroban_sdk::crypto::BnScalar;

let inputs = vec![env, a.clone(), b.clone()];
let hash = poseidon2_hash::<4, BnScalar>(env, &inputs);
```

### Using `crypto_hazmat().poseidon_permutation` (Poseidon)
```rust
let state: Vec<U256> = Vec::from_array(env, [zero, a.clone(), b.clone()]);
let result = env.crypto_hazmat().poseidon_permutation(
    &state,
    Symbol::new(env, "BN254"),
    3,   // t: state width
    5,   // d: S-box degree
    8,   // rf: full rounds
    57,  // rp: partial rounds
    &mds_matrix,
    &round_constants,
);
let hash = result.get(0).unwrap();
```

Ensure the Poseidon parameters (t, d, rf, rp, MDS, round constants) match between circuit and contract.

### Address-to-field conversion for BN254
When binding proofs to Stellar addresses:
```rust
pub fn address_to_field(env: &Env, addr: &Address) -> U256 {
    let bytes: Bytes = addr.to_xdr(env);
    let hash = env.crypto().sha256(&bytes);
    let arr = hash.to_array();
    let mut field = [0u8; 32];
    field[1..32].copy_from_slice(&arr[0..31]); // 31 bytes for BN254 field
    U256::from_be_bytes(env, &Bytes::from_slice(env, &field))
}
```

## Seed generation and anti-replay

Bind proofs to player identity and nonce using Poseidon:
```rust
pub fn generate_seed(env: &Env, player: &Address, nonce: u64) -> U256 {
    let addr_field = address_to_field(env, player);
    let nonce_field = U256::from_u128(env, nonce as u128);
    poseidon2_hash(env, &vec![env, addr_field, nonce_field])
}
```

For stronger domain binding, include contract ID and domain separator:
```rust
#[contracttype]
pub struct DomainBinding {
    pub challenge_id: u32,
    pub player_address: Address,
    pub nonce: u64,
    pub contract_id: Address,
    pub domain_separator: BytesN<32>,
}
```

## Integration checklist
- [ ] SDK pin supports required APIs
- [ ] Proof statement includes anti-replay binding (nonce/context)
- [ ] Full simulation path is covered (proof + policy + state transition)
- [ ] Negative-path tests exist for malformed/tampered inputs
- [ ] Resource budget checks are documented for realistic proof sizes
- [ ] Security review documents all cryptographic assumptions
- [ ] G2 byte order is handled correctly (snarkjs c0|c1 vs Soroban c1|c0) if using Groth16
- [ ] Poseidon parameters match between circuit (Noir/Circom) and on-chain contract
- [ ] Verification keys are stored with admin-gated rotation
- [ ] Mock mode is disabled before mainnet deployment

## Common pitfalls

### G2 byte order mismatch (Groth16)
snarkjs outputs G2 points as `c0|c1`, but the Soroban BN254 SDK expects `c1|c0`. Failing to swap produces silent verification failures.

Mitigation:
- Swap the 32-byte halves of each G2 coordinate at parse time.
- Test with known proof/VK pairs from snarkjs export.

### Poseidon parameter mismatch
Different Poseidon implementations use different parameters (t, rounds, MDS matrices). A hash computed in a Noir circuit will not match the on-chain hash if parameters diverge.

Mitigation:
- Use identical Poseidon configurations: Noir's `poseidon::bn254::hash_2` uses t=3, d=5, rf=8, rp=57.
- Generate and verify test vectors that cross the circuit/contract boundary.
- Use `soroban_poseidon` crate or match `crypto_hazmat` parameters exactly.

### Over-trusting proof payload shape
A payload that parses is not equivalent to a valid statement for your application.

Mitigation:
- Validate public-input semantics and statement domain explicitly.
- Check `vk.ic.len() == public_inputs.len() + 1` before computing the linear combination.
- Validate proof byte length (256 for Groth16, 14624 for UltraHonk).

### Missing anti-replay controls
Valid proofs can be replayed without context binding.

Mitigation:
- Bind proofs to session/nonce/action scope and persist replay guards.
- Store proof hashes after verification: `env.storage().persistent().set(&StorageKey::ProofVerified(proof_hash), &true)`.

### Monolithic contract design
Combining verifier, policy, and state logic increases audit complexity.

Mitigation:
- Keep verifier logic isolated and narrow.
- Use cross-contract calls from application to verifier.
- Assign circuit IDs for multi-circuit applications (e.g., 0=combat, 1=placement, 2=move, 3=victory).

### Hardcoded protocol assumptions
Assuming primitive availability across all networks causes runtime failures.

Mitigation:
- Capability-gate and verify at deployment time.
- Use mock mode (verifier returns `true` when no VK is stored) for development, disable before mainnet.

### Client-side proof generation bottlenecks
Browser-based Noir proof generation via WASM can take 10-30+ seconds for complex circuits.

Mitigation:
- Use Web Workers to avoid blocking the UI thread.
- Show proof generation progress indicators.
- Consider server-side proving for latency-sensitive applications.
- For RISC Zero, proof generation is always server-side.

## Testing strategy

### Unit tests
- Input domain validation
- Replay protection behavior
- Event correctness
- Noir circuit tests with `#[test]` and `#[test(should_fail_with = "...")]` annotations

### Integration tests
- End-to-end proof submission flow
- Negative cases: tampered input, stale nonce, unsupported feature path
- Network-configuration differences (local/testnet/mainnet)
- Cross-boundary hash consistency: generate commitment in Noir, verify it matches on-chain Poseidon output

### Operational tests
- Cost/resource envelope under realistic proof sizes
- Load behavior on verifier hot paths
- Upgrade/migration safety tests for verifier changes

## Security review focus
- Authorization and anti-replay guarantees
- Statement domain separation
- Upgrade controls around verifier/policy modules
- Denial-of-service resistance and bounded workloads
- Event/log coverage for forensic traceability
- G2 byte order correctness
- Poseidon parameter consistency across circuit and contract

## Example starting points
- [Soroban examples](https://github.com/stellar/soroban-examples)
- [Groth16 verifier example](https://github.com/stellar/soroban-examples/tree/main/groth16_verifier)
- [UltraHonk Soroban verifier](https://github.com/yugocabrio/rs-soroban-ultrahonk) - library for Noir/UltraHonk proof verification
- [Security guide](security.md)
- [Advanced patterns](advanced-patterns.md)
- [Standards reference](standards-reference.md)

## References and demos
- [Stellar ZK overview](https://developers.stellar.org/docs/build/apps/zk/overview)
- [Noir Groth16 Demo](https://github.com/jamesbachini/Noir-Groth16)
- [Noir Ultrahonk Demo](https://jamesbachini.com/noir-on-stellar/)
- [Circom Demo](https://github.com/jamesbachini/CircomStellar)
- [RISC Zero Demo](https://github.com/jamesbachini/typezero)

## What not to do
- Do not skip simulation and negative-path testing for verifier flows.
- Do not use snarkjs G2 byte order directly without swapping for Soroban SDK compatibility.
- Do not assume Poseidon parameters match across implementations without verifying with test vectors.
- Do not leave mock mode (VK-absent = always pass) enabled in production deployments.
