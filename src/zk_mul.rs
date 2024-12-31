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

    // t(x) = l(x) * r(x) = (a + s_l*x)(b + s_r*x) = (ab) + (as_r + bs_l)x + (s_l*s_r)x^2
    let t_x = l_x * r_x;

    // l(x) = a + s_l * x
    let a = l_x.coeffs[0];    // constant term 'a'
    let s_l = l_x.coeffs[1];  // coefficient of x: 's_l'

    // r(x) = b + s_r * x
    let b = r_x.coeffs[0];    // constant term 'b'
    let s_r = r_x.coeffs[1];  // coefficient of x: 's_r'

    let alpha = generate_random_field_element();
    // C_a = Com(a,b; α) = g_1^a * g_2^b * h^α
    let _a = pedersen_commitment(&[a, b].to_vec(), g_vec, alpha.clone()).unwrap();

    let beta = generate_random_field_element();
    // C_s = Com(s_l,s_r; β) = g_1^s_l * g_2^s_r * h^β
    let _s = pedersen_commitment(&[s_l, s_r].to_vec(), g_vec, beta.clone()).unwrap();

    let tau_0 = generate_random_field_element();
    // C_t0 = Com(a*b; τ_0) = g_1^(ab) * h^τ_0
    let _t_0 = pedersen_commitment(&[a * b].to_vec(), g_vec, tau_0.clone()).unwrap();

    let tau_1 = generate_random_field_element();
    // C_t1 = Com(a*s_r + b*s_l; τ_1) = g_1^(as_r + bs_l) * h^τ_1
    let _t_1 = pedersen_commitment(&[a * s_r + b * s_l].to_vec(), g_vec, tau_1.clone()).unwrap();

    let tau_2 = generate_random_field_element();
    // C_t2 = Com(s_r*s_l; τ_2) = g_1^(s_r*s_l) * h^τ_2
    let _t_2 = pedersen_commitment(&[s_r * s_l].to_vec(), g_vec, tau_2.clone()).unwrap();

    // Return all commitments and their blinding factors
    (
        [_a, _s, _t_0, _t_1, _t_2].to_vec(),
        [alpha, beta, tau_0, tau_1, tau_2].to_vec(),
    )
}

pub fn generate_proof(blinding_factors: &Vec<F>, u: &F) -> (F, F) {
    let [alpha, beta, tau_0, tau_1, tau_2] = blinding_factors.as_slice() else {
        panic!("Expected exactly 5 blinding factors");
    };

    // π_lr = α + β*u : Linear combination of blinding factors for l(u) and r(u)
    let pi_lr = *alpha + *beta * u;
    // π_t = τ_0 + τ_1*u + τ_2*u^2 : Evaluation of blinding polynomial at point u
    let pi_t = *tau_0 + *tau_1 * u + *tau_2 * u * u;

    (pi_lr, pi_t)
}

pub fn verify_proof(
    committments: &Vec<G1Affine>,
    g_vec: &Vec<G1Affine>,
    proofs: &(F, F),
    u: &F,
    poly_evaluation: &(F, F, F),
) -> bool {
    let [_a, _s, _t_0, _t_1, _t_2] = committments.as_slice() else {
        panic!("Expected exactly 5 blinding factors");
    };

    let (pi_lr, pi_t) = proofs;
    let (l_u, r_u, t_u) = poly_evaluation;

    // Check 1: C_a + u*C_s = Com(l(u),r(u); π_lr)
    // Verifies the commitment to the polynomial evaluations
    let lhs_1 = (*_a + *_s * u).into_affine();
    let rhs_1 = pedersen_commitment(&[*l_u, *r_u].to_vec(), g_vec, *pi_lr).unwrap();

    // Check 2: Com(t(u); π_t) = C_t0 + u*C_t1 + u^2*C_t2
    // Verifies the commitment to the product polynomial evaluation
    let lhs_2 = pedersen_commitment(&[*t_u].to_vec(), g_vec, *pi_t).unwrap();
    let rhs_2 = (*_t_0 + *_t_1 * u + *_t_2 * u * u).into_affine();

    // Check 3: t(u) = l(u) * r(u)
    // Verifies that the claimed polynomial evaluations satisfy the multiplication
    let lhs_3 = *t_u;
    let rhs_3 = l_u * r_u;

    // All three checks must pass for verification to succeed
    (lhs_1 == rhs_1) && (lhs_2 == rhs_2) && (lhs_3 == rhs_3)
}

pub fn generate_random_field_element() -> F {
    let mut rng = rand::thread_rng();
    let num = rng.gen_range(1..100000);
    F::from(num)
}
