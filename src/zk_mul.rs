use std::error::Error;

use ark_bls12_381::{Bls12_381, Config, Fq, Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use num_bigint::BigInt;
use rand::Rng;

use super::pedersen_commitment::pedersen_commitment;

pub fn commit_polynomials(
    l_x: &DensePolynomial<F>,
    r_x: &DensePolynomial<F>,
    g_vec: &Vec<G1Affine>,
) -> (Vec<G1Affine>, Vec<F>) {
    assert!(
        l_x.coeffs.len() == 2,
        "Do not support polynomials with degree higher than 2"
    );
    assert!(
        r_x.coeffs.len() == 2,
        "Do not support polynomials with degree higher than 2"
    );

    let t_x = l_x * r_x;

    let a = l_x.coeffs[0];
    let s_l = l_x.coeffs[1];

    let b = r_x.coeffs[0];
    let s_r = r_x.coeffs[1];

    let alpha = generate_random_field_element();

    let _a = pedersen_commitment(&[a, b].to_vec(), g_vec, alpha.clone()).unwrap();

    let beta = generate_random_field_element();
    let _s = pedersen_commitment(&[s_l, s_r].to_vec(), g_vec, beta.clone()).unwrap();

    let tau_0 = generate_random_field_element();
    let _t_0 = pedersen_commitment(&[a * b].to_vec(), g_vec, tau_0.clone()).unwrap();

    let tau_1 = generate_random_field_element();
    let _t_1 = pedersen_commitment(&[a * s_r + b * s_l].to_vec(), g_vec, tau_1.clone()).unwrap();

    let tau_2 = generate_random_field_element();
    let _t_2 = pedersen_commitment(&[s_r * s_l].to_vec(), g_vec, tau_2.clone()).unwrap();

    (
        [_a, _s, _t_0, _t_1, _t_2].to_vec(),
        [alpha, beta, tau_0, tau_1, tau_2].to_vec(),
    )
}

pub fn generate_proof(blinding_factors: &Vec<F>, u: &F) -> (F, F) {
    let [alpha, beta, tau_0, tau_1, tau_2] = blinding_factors.as_slice() else {
        panic!("Expected exactly 5 blinding factors");
    };

    let pi_lr = *alpha + *beta * u;
    let pi_t = *tau_0 + *tau_1 * u + *tau_2 * u * u;

    (pi_lr, pi_t)
}


pub fn verify_proof(committments: &Vec<G1Affine>, g_vec: &Vec<G1Affine>, proofs: &(F, F), u: &F, poly_evaluation: &(F, F, F)) -> bool {
  let [_a, _s, _t_0, _t_1, _t_2] = committments.as_slice() else {
    panic!("Expected exactly 5 blinding factors");
  };

  let (pi_lr, pi_t) = proofs;

  let (l_u, r_u, t_u) = poly_evaluation;

  let lhs_1 = (*_a + *_s * u).into_affine();
  let rhs_1 = pedersen_commitment(&[*l_u, *r_u].to_vec(), g_vec, *pi_lr).unwrap();

  let lhs_2 = pedersen_commitment(&[*t_u].to_vec(), g_vec, *pi_t).unwrap();
  let rhs_2 = (*_t_0 + *_t_1 * u + *_t_2 * u * u).into_affine();

  let lhs_3 = *t_u;
  let rhs_3 = l_u * r_u;

  (lhs_1 == rhs_1) && (lhs_2 == rhs_2) && (lhs_3 == rhs_3)

}

pub fn generate_random_field_element() -> F {
    let mut rng = rand::thread_rng();
    let num = rng.gen_range(1..100000);
    F::from(num)
}
