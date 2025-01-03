use std::error::Error;

use ark_bls12_381::{Bls12_381, Config, Fq, Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};
use blake3::{self, Hash};

pub fn pedersen_commitment(
    committing_vector: &Vec<F>,
    g_vec: &Vec<G1Affine>,
    blinding_factor: F,
) -> Result<G1Affine, Box<dyn Error>> {
    if (committing_vector.len() + 1) > g_vec.len() {
        return Err("Invalid vector lengths".into());
    }
    // Pedersen commitment: C = ∑(v_i * G_i) + r * H
    // where v_i are the values, G_i are the generators, r is the blinding factor, and H is the last generator
    let mut result: G1Affine = G1Affine::zero();
    for (index, point) in committing_vector.iter().enumerate() {
        // Accumulate v_i * G_i terms
        result = (result.into_group() + g_vec[index] * point).into_affine();
    }
    // Add blinding factor term: r * H
    result = (result.into_group() + *g_vec.last().unwrap() * blinding_factor).into();
    Ok(result)
}

pub fn commit(
    committing_vector: &Vec<F>,
    g_vec: &Vec<G1Affine>,
) -> Result<G1Affine, Box<dyn Error>> {
    if committing_vector.len() != g_vec.len() {
        return Err("Invalid vector lengths".into());
    }
    // Simple commitment without blinding: C = ∑(v_i * G_i)
    let mut result: G1Affine = G1Affine::zero();
    for (index, point) in committing_vector.iter().enumerate() {
        // Accumulate v_i * G_i terms
        result = (result + g_vec[index] * point).into_affine();
    }
    Ok(result)
}

fn generate_random_point(seed: String) -> (G1Affine, Hash) {
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
    // BLS12-381 curve equation: y² = x³ + 4
    let x_cubed = x * x * x;
    let rhs = x_cubed + Fq::from(4);
    rhs.sqrt()
}
