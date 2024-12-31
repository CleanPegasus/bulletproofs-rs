use bulletproofs_rs::random_ec_points::generate_n_random_points;

use bulletproofs_rs::log_proof_commitment::verify_log_proof_of_committment;

use ark_bn254::{Fr as F, G1Affine};

#[test]
fn test_log_proof_verification() {
    let mut commiting_vector = vec![F::from(1), F::from(3), F::from(4)];

    let mut g_vec = generate_n_random_points("hello".to_string(), 3);

    let verification = verify_log_proof_of_committment(&mut commiting_vector, &mut g_vec);

    assert!(verification);
}
