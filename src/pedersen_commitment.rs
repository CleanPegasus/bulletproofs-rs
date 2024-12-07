use std::error::Error;

use ark_bls12_381::{
    Bls12_381, Config, Fq, Fr as F, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    pairing::Pairing,
    short_weierstrass::Affine,
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{BigInteger256, Field, PrimeField, UniformRand, Zero};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};
use blake3::{self, Hash};
use num_bigint::BigInt;

pub fn pedersen_commitment(
    committing_vector: &Vec<F>,
    g_vec: &Vec<G1Affine>,
    blinding_factor: F,
) -> Result<G1Affine, Box<dyn Error>> {
    if committing_vector.len() != (g_vec.len() + 1) {
        return Err("Invalid vector lengths".into());
    }

    let mut result: G1Affine = G1Affine::zero();

    for (index, point) in committing_vector.iter().enumerate() {
        result = (result.into_group() + g_vec[index] * point).into_affine();
    }
    result = (result.into_group() + *g_vec.last().unwrap() * blinding_factor).into();
    Ok(result)
}

pub fn generate_random_point(seed: String) -> (G1Affine, Hash) {
    let hash = blake3::hash(seed.as_bytes());
    let next_hash = blake3::hash(hash.as_bytes());
    let mut x = Fq::from_le_bytes_mod_order(hash.as_bytes());
    let mut y;

    loop {
        if let Some(y_value) = find_y_for_x(x) {
            y = y_value;
            let point = G1Affine::new_unchecked(x, y);
            if point.is_on_curve() {
                return (point, next_hash);
            }
        }
        x = x + Fq::from(1);
    }
}

pub fn generate_n_random_points(seed: String, num_point: i32) -> Vec<G1Affine> {
    let mut random_points = Vec::<G1Affine>::new();
    let mut current_seed = seed;
    for _ in 0..num_point {
        let (point, next_seed) = generate_random_point(current_seed);
        random_points.push(point);
        current_seed = next_seed.to_string();
    }
    random_points
}

fn find_y_for_x(x: Fq) -> Option<Fq> {
    // y^2 = x^3 + 4
    let x_cubed = x * x * x;
    let rhs = x_cubed + Fq::from(4);
    rhs.sqrt()
}
