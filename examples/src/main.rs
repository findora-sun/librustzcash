use bellman::groth16::{create_random_proof, generate_random_parameters};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Bls12;
use group::{
    ff::{Field, PrimeField, PrimeFieldBits},
    Curve, Group,
};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::time::Instant;
use zcash_primitives::sapling::{
    pedersen_hash, Diversifier, Note, ProofGenerationKey, Rseed, ValueCommitment,
};
use zcash_proofs::circuit::sapling::{Output, Spend};

const TREE_DEPTH: usize = 32;

struct Utxo {
    inputs: [Spend; 6],
    outputs: [Output; 6],
}

impl Circuit<bls12_381::Scalar> for Utxo {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        for i in self.inputs {
            i.synthesize(cs)?;
        }

        for o in self.outputs {
            o.synthesize(cs)?;
        }

        Ok(())
    }
}

fn main() {
    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let empty_spend = Spend {
        value_commitment: None,
        proof_generation_key: None,
        payment_address: None,
        commitment_randomness: None,
        ar: None,
        auth_path: vec![None; TREE_DEPTH],
        anchor: None,
    };
    let empty_output = Output {
        value_commitment: None,
        payment_address: None,
        commitment_randomness: None,
        esk: None,
    };

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Utxo {
            inputs: [
                empty_spend.clone(),
                empty_spend.clone(),
                empty_spend.clone(),
                empty_spend.clone(),
                empty_spend.clone(),
                empty_spend.clone(),
            ],
            outputs: [
                empty_output.clone(),
                empty_output.clone(),
                empty_output.clone(),
                empty_output.clone(),
                empty_output.clone(),
                empty_output.clone(),
            ],
        },
        &mut rng,
    )
    .unwrap();

    let tree_depth = 32;

    let value_commitment = ValueCommitment {
        value: rng.next_u64(),
        randomness: jubjub::Fr::random(&mut rng),
    };

    let proof_generation_key = ProofGenerationKey {
        ak: jubjub::SubgroupPoint::random(&mut rng),
        nsk: jubjub::Fr::random(&mut rng),
    };

    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address;

    loop {
        let diversifier = {
            let mut d = [0; 11];
            rng.fill_bytes(&mut d);
            Diversifier(d)
        };

        if let Some(p) = viewing_key.to_payment_address(diversifier) {
            payment_address = p;
            break;
        }
    }

    let g_d = payment_address.diversifier().g_d().unwrap();
    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let auth_path =
        vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];
    let ar = jubjub::Fr::random(&mut rng);

    let input = {
        let _receive_key = jubjub::ExtendedPoint::from(viewing_key.rk(ar)).to_affine();
        let _expected_value_commitment =
            jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
        let note = Note {
            value: value_commitment.value,
            g_d,
            pk_d: *payment_address.pk_d(),
            rseed: Rseed::BeforeZip212(commitment_randomness),
        };

        let mut _position = 0u64;
        let cmu = note.cmu();
        let mut cur = cmu;

        for (i, val) in auth_path.clone().into_iter().enumerate() {
            let (uncle, b) = val.unwrap();

            let mut lhs = cur;
            let mut rhs = uncle;

            if b {
                ::std::mem::swap(&mut lhs, &mut rhs);
            }

            let lhs = lhs.to_le_bits();
            let rhs = rhs.to_le_bits();

            cur = jubjub::ExtendedPoint::from(pedersen_hash::pedersen_hash(
                pedersen_hash::Personalization::MerkleTree(i),
                lhs.iter()
                    .by_vals()
                    .take(bls12_381::Scalar::NUM_BITS as usize)
                    .chain(
                        rhs.iter()
                            .by_vals()
                            .take(bls12_381::Scalar::NUM_BITS as usize),
                    ),
            ))
            .to_affine()
            .get_u();

            if b {
                _position |= 1 << i;
            }
        }

        Spend {
            value_commitment: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            payment_address: Some(payment_address.clone()),
            commitment_randomness: Some(commitment_randomness),
            ar: Some(ar),
            auth_path: auth_path.clone(),
            anchor: Some(cur),
        }
    };

    let output = {
        let value_commitment = ValueCommitment {
            value: rng.next_u64(),
            randomness: jubjub::Fr::random(&mut rng),
        };

        let nsk = jubjub::Fr::random(&mut rng);
        let ak = jubjub::SubgroupPoint::random(&mut rng);

        let proof_generation_key = ProofGenerationKey { ak, nsk };

        let viewing_key = proof_generation_key.to_viewing_key();

        let payment_address;

        loop {
            let diversifier = {
                let mut d = [0; 11];
                rng.fill_bytes(&mut d);
                Diversifier(d)
            };

            if let Some(p) = viewing_key.to_payment_address(diversifier) {
                payment_address = p;
                break;
            }
        }

        let commitment_randomness = jubjub::Fr::random(&mut rng);
        let esk = jubjub::Fr::random(&mut rng);

        Output {
            value_commitment: Some(value_commitment.clone()),
            payment_address: Some(payment_address.clone()),
            commitment_randomness: Some(commitment_randomness),
            esk: Some(esk),
        }
    };

    let utxo = Utxo {
        inputs: [
            input.clone(),
            input.clone(),
            input.clone(),
            input.clone(),
            input.clone(),
            input.clone(),
        ],
        outputs: [
            output.clone(),
            output.clone(),
            output.clone(),
            output.clone(),
            output.clone(),
            output.clone(),
        ],
    };

    let start = Instant::now();
    let _proof = create_random_proof(utxo, &groth_params, &mut rng);
    println!("Create proof time: {:?}", start.elapsed());
}
