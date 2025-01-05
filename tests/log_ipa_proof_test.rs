use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, UniformRand};
use bulletproofs_rs::{
    log_ipa_proof::{fold_field, fold_points, log_ipa_proof},
    random_ec_points::generate_n_random_points,
};

use ark_bn254::{Fr as F, G1Affine};
use rand::thread_rng;

#[test]
fn test_log_ipa() {
    let mut a = vec![F::from(2), F::from(3), F::from(7), F::from(6)];
    let mut b = vec![F::from(5), F::from(4), F::from(9), F::from(1)];

    let mut g_vec = generate_n_random_points("hello".to_string(), 4);
    let mut h_vec = generate_n_random_points("bullet".to_string(), 4);
    let q = generate_n_random_points("proof".to_string(), 1)[0];

    let verification = log_ipa_proof(a, b, g_vec, h_vec, q);

    assert!(verification)
}

#[test]
fn test_fold_field() {
    let mut rng = thread_rng();
    let u = F::rand(&mut rng);

    // Test with odd length vector to verify padding behavior
    let input = vec![
        F::rand(&mut rng),
        F::rand(&mut rng),
        F::rand(&mut rng),
        F::rand(&mut rng),
    ];
    let original_input = input.clone();

    let result = fold_field(input, &u);

    // Check length is (original_length + 1) / 2
    assert_eq!(result.len(), 2);

    // Verify first folded element
    let expected_first = original_input[0] * u + original_input[1] * u.inverse().unwrap();
    assert_eq!(result[0], expected_first);

    // Verify second folded element (with padding)
    let expected_second = original_input[2] * u + original_input[3] * u.inverse().unwrap();
    assert_eq!(result[1], expected_second);

}

#[test]
fn test_fold_points() {
    let mut rng = thread_rng();
    let u = F::rand(&mut rng);

    // Create random group elements (odd length to test padding)
    let g = G1Affine::generator();
    let input = vec![
        (g * F::rand(&mut rng)).into_affine(),
        (g * F::rand(&mut rng)).into_affine(),
        (g * F::rand(&mut rng)).into_affine(),
        (g * F::rand(&mut rng)).into_affine()
    ];
    let original_input = input.clone();

    let result = fold_points(input, &u);

    // Check length is (original_length + 1) / 2
    assert_eq!(result.len(), 2);

    // Verify first folded element
    let expected_first: G1Affine =
        (original_input[0] * u + original_input[1] * u.inverse().unwrap()).into_affine();
    assert_eq!(result[0], expected_first);

    // Verify second folded element (with padding)
    let expected_second =
        (original_input[2] * u + original_input[3] * u.inverse().unwrap()).into_affine();
    assert_eq!(result[1], expected_second);

}
