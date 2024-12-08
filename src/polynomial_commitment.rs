use std::error::Error;

use ark_bls12_381::{
    Bls12_381, Config, Fq, Fr as F, G1Affine
};
use ark_ec::{
    AffineRepr, CurveGroup,
};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};
use blake3::{self, Hash};
use super::pedersen_commitment::pedersen_commitment;

pub fn commit_polynomial(poly: &DensePolynomial<F>, gammas: &Vec<F>, g: &G1Affine, b: &G1Affine) -> Result<Vec<G1Affine>, Box<dyn Error>> {
  let coeffs = Vec::from(poly.coeffs());
  if coeffs.len() != gammas.len() {
    return Err("Invalid gammas length".into())
  }
  let mut results = Vec::<G1Affine>::new();
  for (index, coeff) in coeffs.into_iter().enumerate() {
    results.push(pedersen_commitment(&[coeff].to_vec(), &[*g].to_vec(), gammas[index])?);
  }
  Ok(results)
}

pub fn generate_proof(gammas: &Vec<F>, u: &F) -> F {
  let mut proof = F::ZERO;

  gammas.iter().enumerate().for_each(|(index, gamma)| {
    proof = proof + *gamma * u.pow(&[index as u64])
  });

  proof
}

pub fn verify(commitments: Vec<G1Affine>, g: &G1Affine, b: &G1Affine, u: &F, f_u: &F, proof: &F) -> bool {
  let mut lhs = G1Affine::zero();
  commitments.iter().enumerate().for_each(|(index, commitment)| {
    let u_powered = u.pow(&[index as u64]);
    lhs = (lhs + (*commitment * u_powered).into_affine()).into();
  });

  let rhs = (*g * f_u + *b * u).into_affine();

  lhs == rhs
}

