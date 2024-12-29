use std::error::Error;

use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};


pub fn commit(committing_vector: &Vec<F>, g_vec: &Vec<G1Affine>) -> Result<G1Affine, Box<dyn Error>> {
    if committing_vector.len() != g_vec.len() {
        return Err("Invalid vector lengths".into());
    }
    let mut result: G1Affine = G1Affine::zero();
    for (index, point) in committing_vector.iter().enumerate() {
        result = (result + g_vec[index] * point).into_affine();
    }
    Ok(result)
}

pub fn commit_vector(a: &mut Vec<F>, g_vec: &mut Vec<G1Affine>) -> (G1Affine, G1Affine, G1Affine) {

    let _a = commit(a, g_vec).unwrap();

    let (_l, _r) = compute_secondary_diagonal(g_vec, a);

    (_a, _l, _r)
}

pub fn verify_succinct_proof(
    committments: &(G1Affine, G1Affine, G1Affine),
    proof: &Vec<F>,
    u: &F,
    g_vec: &mut Vec<G1Affine>,
) -> bool {
    let (_a, _l, _r) = committments;

    let u_square_inv = (u * u).inverse().unwrap();
    let l_u_squared = (*_l * u * u).into_affine();
    let r_u_inv_squared = (*_r * u_square_inv).into_affine();
    let lhs = (l_u_squared + *_a + r_u_inv_squared).into_affine();
    // let lhs = ((*_l * u * u) + _a + *_r * u_square_inv).into_affine();

    let u_inv = u.inverse().unwrap();
    let folded_g_vec = fold_group(g_vec, &u_inv);
    let rhs = commit(proof, &folded_g_vec).unwrap();

    lhs == rhs
}

pub fn fold_field(a: &mut Vec<F>, u: &F) -> Vec<F> {
    if a.len() % 2 != 0 {
        a.push(F::ZERO);
    }

    let mut result = Vec::<F>::new();
    for chunk in a.chunks(2) {
        result.push(chunk[0] * u + chunk[1] * u.inverse().unwrap());
    }

    result
}

pub fn fold_group(a: &mut Vec<G1Affine>, u: &F) -> Vec<G1Affine> {
    if a.len() % 2 != 0 {
        a.push(G1Affine::zero());
    }
    a.chunks(2)
        .map(|chunk| (chunk[0] * u + chunk[1] * u.inverse().unwrap()).into_affine())
        .collect()
}

pub fn split_vector<T: Clone + Default>(a: &mut Vec<T>) -> (Vec<T>, Vec<T>) {
    if a.len() % 2 != 0 {
        a.push(T::default());
    }
    let l: Vec<T> = a.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let r: Vec<T> = a.chunks(2).map(|chunk| chunk[1].clone()).collect();
    (l, r)
}

pub fn compute_secondary_diagonal(g_vec: &mut Vec<G1Affine>, a: &mut Vec<F>) -> (G1Affine, G1Affine) {
    if a.len() % 2 != 0 {
        a.push(F::ZERO);
        g_vec.push(G1Affine::zero());
    }

    let l: Vec<F> = a.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let r: Vec<F> = a.chunks(2).map(|chunk| chunk[1].clone()).collect();

    let g1_vec: Vec<G1Affine> = g_vec.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let g2_vec: Vec<G1Affine> = g_vec.chunks(2).map(|chunk| chunk[1].clone()).collect();


    (commit(&l, &g2_vec).unwrap(), commit(&r, &g1_vec).unwrap())
}
