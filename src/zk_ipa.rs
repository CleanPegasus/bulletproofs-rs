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

use crate::{vector_polynomial::{InnerProduct, VectorPolynomial}, zk_mul::generate_random_field_element};

pub fn committment_vector_polynomials(
    l_x: VectorPolynomial,
    r_x: VectorPolynomial,
    g_vec: &Vec<G1Affine>,
    h_vec: &Vec<G1Affine>,
    _g: &G1Affine,
    _b: &G1Affine,
) -> (Vec<G1Affine>, Vec<F>) {

    assert!(l_x.len() == r_x.len() && l_x.len() == 2);

    assert!(g_vec.len() == h_vec.len() && g_vec.len() == 2);

    let a = l_x[0].clone();
    let s_l = l_x[1].clone();

    let b = r_x[0].clone();
    let s_r = r_x[0].clone();

    let v = a.clone() * b.clone();

    let alpha = generate_random_field_element();
    let _a = (a.commit(g_vec) + b.commit(h_vec) + (*_b * alpha).into_affine()).into_affine();

    let beta = generate_random_field_element();
    let _s = (s_l.commit(g_vec) + s_r.commit(h_vec) + (*_b * beta)).into_affine();

    let gamma = generate_random_field_element();
    let _v = (v.commit(g_vec) + *_b * gamma).into_affine();

    let tau_1 = generate_random_field_element();
    let _t_1 = (*_g *(a.inner_product(&s_r) + b.inner_product(&s_l)) + *_b * tau_1).into_affine();

    let tau_2 = generate_random_field_element();
    let _t_2 = (*_g * s_l.inner_product(&s_r) + *_b * tau_2).into_affine();

    return (vec![_a, _s, _v, _t_1, _t_2], vec![alpha, beta, gamma, tau_1, tau_2]);

}

