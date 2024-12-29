use std::error::Error;

use ark_bn254::{Config, Fq, Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, Polynomial,
};
use ark_std::{rand, One};
use sha256::digest;
use rand::Rng;

fn generate_random_point(seed: String) -> (G1Affine, String) {
  let hash = digest(seed.as_bytes());
  let next_hash = digest(hash.as_bytes());
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
  // y^2 = x^3 + 3
  let x_cubed = x * x * x;
  let rhs = x_cubed + Fq::from(3);
  rhs.sqrt()
}

pub fn generate_random_field_element() -> F {
  let mut rng = rand::thread_rng();
  let num = rng.gen_range(1..100000);
  F::from(num)
}