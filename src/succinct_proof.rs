use std::error::Error;

use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};

/// Computes the commitment C which is the sum of each generator g_i multiplied by the corresponding scalar a_i
pub fn commit(
    committing_vector: &Vec<F>,
    g_vec: &Vec<G1Affine>,
) -> Result<G1Affine, Box<dyn Error>> {
    if committing_vector.len() != g_vec.len() {
        return Err("Invalid vector lengths".into());
    }
    let mut result: G1Affine = G1Affine::zero();
    for (index, point) in committing_vector.iter().enumerate() {
        // C += g_i * a_i
        result = (result + g_vec[index] * point).into_affine();
    }
    Ok(result)
}

/// Computes the commitments C_a, L, and R by committing to vectors a, l, and r respectively
pub fn commit_vector(a: &mut Vec<F>, g_vec: &mut Vec<G1Affine>) -> (G1Affine, G1Affine, G1Affine) {
    let _a = commit(a, g_vec).unwrap();

    let (_l, _r) = compute_secondary_diagonal(g_vec, a);

    (_a, _l, _r)
}

/// Verifies the succinct proof by checking if L multiplied by u squared plus C_a plus R multiplied by u inverse squared equals C_proof
pub fn verify_succinct_proof(
    committments: &(G1Affine, G1Affine, G1Affine),
    proof: &Vec<F>,
    u: &F,
    g_vec: &mut Vec<G1Affine>,
) -> bool {
    let (_a, _l, _r) = committments;

    // Compute u squared inverse
    let u_square_inv = (u * u).inverse().unwrap();
    // Compute L multiplied by u squared
    let l_u_squared = (*_l * u * u).into_affine();
    // Compute R multiplied by u inverse squared
    let r_u_inv_squared = (*_r * u_square_inv).into_affine();
    // Compute left-hand side: L * u^2 + C_a + R * u^{-2}
    let lhs = (l_u_squared + *_a + r_u_inv_squared).into_affine();

    // Fold the generator vector with u inverse
    let u_inv = u.inverse().unwrap();
    let folded_g_vec = fold_group(g_vec, &u_inv);
    // Compute right-hand side: C_proof is commit(proof, folded_g_vec)
    let rhs = commit(proof, &folded_g_vec).unwrap();

    lhs == rhs
}

/// Folds the field vector a into a new vector a_prime where each element a'_i is a_2i multiplied by u plus a_2i+1 multiplied by u inverse
pub fn fold_field(a: &mut Vec<F>, u: &F) -> Vec<F> {
    if a.len() % 2 != 0 {
        a.push(F::ZERO);
    }

    let mut result = Vec::<F>::new();
    for chunk in a.chunks(2) {
        // a_prime = a_0 * u + a_1 * u_inverse
        result.push(chunk[0] * u + chunk[1] * u.inverse().unwrap());
    }

    result
}

/// Folds the group vector G into a new vector G_prime where each element G'_i is G_2i multiplied by u plus G_2i+1 multiplied by u inverse
pub fn fold_group(a: &mut Vec<G1Affine>, u: &F) -> Vec<G1Affine> {
    if a.len() % 2 != 0 {
        a.push(G1Affine::zero());
    }
    a.chunks(2)
        .map(|chunk| {
            // G_prime = G_0 * u + G_1 * u_inverse
            (chunk[0] * u + chunk[1] * u.inverse().unwrap()).into_affine()
        })
        .collect()
}

/// Splits the vector a into two vectors l and r where each element l_i is a_2i and r_i is a_2i+1
pub fn split_vector<T: Clone + Default>(a: &mut Vec<T>) -> (Vec<T>, Vec<T>) {
    if a.len() % 2 != 0 {
        a.push(T::default());
    }
    let l: Vec<T> = a.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let r: Vec<T> = a.chunks(2).map(|chunk| chunk[1].clone()).collect();
    (l, r)
}

/// Computes the secondary diagonal commitments L and R by committing to vectors l and r with generators g' and g'' respectively
pub fn compute_secondary_diagonal(
    g_vec: &mut Vec<G1Affine>,
    a: &mut Vec<F>,
) -> (G1Affine, G1Affine) {

    assert_eq!(a.len(), g_vec.len(), "length of Vec a need to match length og g_vec vector");

    if a.len() % 2 != 0 {
        a.push(F::ZERO);
        g_vec.push(G1Affine::zero());
    }

    // Split a into l and r
    let l: Vec<F> = a.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let r: Vec<F> = a.chunks(2).map(|chunk| chunk[1].clone()).collect();

    // Split g into g_prime and g_double_prime
    let g1_vec: Vec<G1Affine> = g_vec.chunks(2).map(|chunk| chunk[0].clone()).collect();
    let g2_vec: Vec<G1Affine> = g_vec.chunks(2).map(|chunk| chunk[1].clone()).collect();


    // Compute L by committing to l with g2_vec and R by committing to r with g1_vec
    (commit(&l, &g2_vec).unwrap(), commit(&r, &g1_vec).unwrap())
}
