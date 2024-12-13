use std::{
    error::Error,
    fmt::Display,
    ops::{Add, Mul},
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

#[derive(Clone)]
pub struct Coeff(pub Vec<F>);

impl Coeff {
    pub fn zero(len: usize) -> Self {
        Self(vec![F::ZERO; len])
    }
}

pub struct VectorPolynomial {
    pub coeffs: Vec<Coeff>,
}

impl Add for Coeff {
    type Output = Coeff;
    fn add(self, rhs: Self) -> Self::Output {
        assert!(self.0.len() == rhs.0.len());
        let coeff = self.0.into_iter().zip(rhs.0).map(|(a, b)| a + b).collect();
        Coeff(coeff)
    }
}

impl Mul for Coeff {
    type Output = F;
    fn mul(self, rhs: Self) -> Self::Output {
        assert!(self.0.len() == rhs.0.len());
        let mut result = F::ZERO;
        self.0
            .into_iter()
            .zip(rhs.0)
            .for_each(|(a, b)| result += a * b);
        result
    }
}

impl VectorPolynomial {
    pub fn new(coeffs: Vec<Coeff>) -> Self {
        let coeffs_len: Vec<usize> = coeffs.iter().map(|coeff| coeff.0.len()).collect();
        assert!(
            coeffs_len.windows(2).all(|w| w[0] == w[1]),
            "All coefficient vectors must have the same length"
        );
        Self { coeffs }
    }

    pub fn evaluate(&self, x: &F) -> Coeff {
        let mut result: Coeff = Coeff::zero(self.coeffs.len());
        self.coeffs.iter().enumerate().for_each(|(index, coeff)| {
            let term: Vec<F> = coeff
                .0
                .iter()
                .map(|&val| val * x.pow(&[index as u64]))
                .collect();
            result = result.clone() + Coeff(term);
        });
        result
    }
}

impl Display for VectorPolynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if i > 0 {
                write!(f, " + ")?;
            }
            write!(f, "(")?;
            for (j, val) in coeff.0.iter().enumerate() {
                if j > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", val)?;
            }
            write!(f, ")x^{}", i)?;
        }
        Ok(())
    }
}

// // Performs inner product
// impl Mul for VectorPolynomial {
//     type Output = DensePolynomial<F>;

//     fn mul(self, rhs: Self) -> Self::Output {
//         assert!(self.coeffs.len() == rhs.coeffs.len());
//     }
// }
