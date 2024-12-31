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

pub fn commit_polynomial(
    poly: &DensePolynomial<F>,
    gammas: &Vec<F>,
    g: &G1Affine,
    b: &G1Affine,
) -> Result<Vec<G1Affine>, Box<dyn Error>> {
    let coeffs = Vec::from(poly.coeffs());
    if coeffs.len() != gammas.len() {
        return Err("Invalid gammas length".into());
    }
    let mut results = Vec::<G1Affine>::new();
    for (index, coeff) in coeffs.into_iter().enumerate() {
        dbg!((index, &coeff));
        // For each coefficient c_i and random value γ_i:
        // Compute commitment_i = c_i * G + γ_i * B
        // This creates a Pedersen commitment for each coefficient
        let committment = *g * coeff + *b * gammas[index];
        results.push(committment.into_affine());
    }
    Ok(results)
}

pub fn generate_proof(gammas: &Vec<F>, u: &F) -> F {
    let mut proof = F::ZERO;
    // Compute π = Σ(γ_i * u^i) for i from 0 to n-1
    // This aggregates the random values (gammas) with powers of the evaluation point
    gammas
        .iter()
        .enumerate()
        .for_each(|(index, gamma)| proof = proof + (*gamma * u.pow(&[index as u64])));

    proof
}

pub fn verify(
    commitments: &Vec<G1Affine>,
    g: &G1Affine,
    b: &G1Affine,
    u: &F,
    f_u: &F,
    proof: &F,
) -> bool {
    let mut lhs = G1Affine::zero();
    // Left-hand side: Σ(C_i * u^i) for i from 0 to n-1
    // Where C_i are the commitments and u is the evaluation point
    commitments
        .iter()
        .enumerate()
        .for_each(|(index, commitment)| {
            let u_i = u.pow(&[index as u64]);
            lhs = (lhs + (*commitment * u_i).into_affine()).into();
        });

    // Right-hand side: f(u) * G + π * B
    // Where f(u) is the polynomial evaluated at u, and π is the proof
    let rhs = ((*g * f_u) + (*b * proof)).into_affine();

    // Verification succeeds if LHS = RHS
    lhs == rhs
}
