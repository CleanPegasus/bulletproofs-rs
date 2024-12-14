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

#[derive(Clone, Debug)]
pub struct Coeff(pub Vec<F>);

impl Coeff {
    pub fn new(values: Vec<F>) -> Self {
        Self(values)
    }

    pub fn commit(&self, g_vec: &Vec<G1Affine>) -> G1Affine {
        assert!(self.len() == g_vec.len());
        self.0
            .iter()
            .zip(g_vec.iter())
            .fold(G1Affine::zero(), |acc, (a, g)| (acc + (*g * a).into_affine()).into())
    }

    pub fn from_slice(values: &[F]) -> Self {
        Self(values.to_vec())
    }

    pub fn zero(len: usize) -> Self {
        Self(vec![F::ZERO; len])
    }

    pub fn one(len: usize) -> Self {
        Self(vec![F::ONE; len])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<F>> for Coeff {
    fn from(values: Vec<F>) -> Self {
        Self(values)
    }
}

impl From<Coeff> for Vec<F> {
    fn from(coeff: Coeff) -> Self {
        coeff.0
    }
}

impl std::ops::Index<usize> for Coeff {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl std::ops::IndexMut<usize> for Coeff {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

pub trait InnerProduct {
    type Output;

    fn inner_product(&self, rhs: &Self) -> Self::Output;
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

impl InnerProduct for Coeff {
    type Output = F;
    fn inner_product(&self, rhs: &Self) -> Self::Output {
        assert!(self.0.len() == rhs.0.len());
        let mut result = F::ZERO;
        self.clone().0
            .into_iter()
            .zip(rhs.0.clone())
            .for_each(|(a, b)| result += a * b);
        result
    }
}

impl Mul for Coeff {
    type Output = Coeff;
    fn mul(self, rhs: Self) -> Self::Output {
        assert!(self.0.len() == rhs.0.len());
        let mut result = Vec::new();
        self.0
            .into_iter()
            .zip(rhs.0)
            .for_each(|(a, b)| result.push(a * b));
        Coeff(result)
    }
}

impl PartialEq for Coeff {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        self.0.iter().zip(other.0.iter()).all(|(a, b)| a == b)
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

    pub fn len(&self) -> usize {
        self.coeffs.len()
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
impl Mul for VectorPolynomial {
    type Output = DensePolynomial<F>;

    fn mul(self, rhs: Self) -> Self::Output {
        assert!(self.coeffs[0].0.len() == rhs.coeffs[0].0.len());

        let result_len = self.coeffs.len() * rhs.coeffs.len();
        let mut result_coeffs = vec![F::ZERO; result_len];

        for (i_index, i_coeff) in self.coeffs.iter().enumerate() {
            for (j_index, j_coeff) in rhs.coeffs.iter().enumerate() {
                let result_term = i_coeff.clone() * j_coeff.clone();
                result_coeffs[j_index + i_index] += result_term.0.iter().sum::<F>();
            }
        }

        DensePolynomial::from_coefficients_vec(result_coeffs)
    }
}

impl std::ops::Index<usize> for VectorPolynomial {
    type Output = Coeff;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

impl std::ops::IndexMut<usize> for VectorPolynomial {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeffs[index]
    }
}
