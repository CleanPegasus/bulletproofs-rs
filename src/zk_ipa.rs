use std::{
    error::Error,
    fmt::Display,
    ops::{Add, Mul},
    process::Output,
};

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

use crate::{
    vector_polynomial::{Coeff, InnerProduct, VectorPolynomial},
    zk_mul::generate_random_field_element,
};

pub use crate::zk_mul::{ verify_proof};

pub fn committment_vector_polynomials(
    l_x: VectorPolynomial,
    r_x: VectorPolynomial,
    g_vec: &Vec<G1Affine>,
    h_vec: &Vec<G1Affine>,
    _g: &G1Affine,
    _b: &G1Affine,
) -> (Vec<G1Affine>, Vec<F>) {
    assert!(l_x.len() == r_x.len() && l_x.len() == 2);

    assert!(g_vec.len() == h_vec.len());

    let a = l_x[0].clone();
    let s_l = l_x[1].clone();

    let b = r_x[0].clone();
    let s_r = r_x[1].clone();

    let v = a.inner_product(&b);

    let alpha = generate_random_field_element();
    let _a = (a.commit(g_vec) + b.commit(h_vec) + (*_b * alpha).into_affine()).into_affine();

    let beta = generate_random_field_element();
    let _s = (s_l.commit(g_vec) + s_r.commit(h_vec) + (*_b * beta)).into_affine();

    let gamma = generate_random_field_element();
    let _v = ( *_g * v + *_b * gamma).into_affine();

    let tau_1 = generate_random_field_element();
    let _t_1 = (*_g * (a.inner_product(&s_r) + b.inner_product(&s_l)) + *_b * tau_1).into_affine();

    let tau_2 = generate_random_field_element();
    let _t_2 = (*_g * s_l.inner_product(&s_r) + *_b * tau_2).into_affine();

    return (
        vec![_a, _s, _v, _t_1, _t_2],
        vec![alpha, beta, gamma, tau_1, tau_2],
    );
}

pub fn generate_proof(blinding_factors: &Vec<F>, u: &F) -> (F, F) {
  let [alpha, beta, gamma, tau_1, tau_2] = blinding_factors.as_slice() else {
      panic!("Expected exactly 5 blinding factors");
  };

  let pi_lr = *alpha + *beta * u;
  let pi_t = *gamma + *tau_1 * u + *tau_2 * u * u;

  (pi_lr, pi_t)
}

pub fn verify_ipa(
    l_u: Coeff,
    r_u: Coeff,
    t_u: &F,
    u: &F,
    committments: &Vec<G1Affine>,
    proofs: &(F, F),
    g_vec: Vec<G1Affine>,
    h_vec: Vec<G1Affine>,
    _g: &G1Affine,
    _b: &G1Affine,
) -> bool {

  let [_a, _s, _v, _t_1, _t_2] = committments.as_slice() else {
    panic!("Expected exactly 5 blinding factors");
  };

  let (pi_lr, pi_t) = proofs;

  let lhs_1 = (*_a + (*_s * u).into_affine()).into_affine();
  let rhs_1 = (l_u.commit(&g_vec) + r_u.commit(&h_vec) + (*_b * pi_lr).into_affine()).into_affine();

  let lhs_2 = (*_g * t_u + *_b * pi_t).into_affine();
  let rhs_2 = (*_v + (*_t_1 * u + *_t_2 * (u * u)).into_affine()).into_affine();

  (lhs_1 == rhs_1) && (lhs_2 == rhs_2) && (*t_u == l_u.inner_product(&r_u))

}
