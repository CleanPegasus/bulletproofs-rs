use super::succinct_proof::{commit, compute_secondary_diagonal, fold_field, fold_group};

use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};

pub fn inner_product(val_1: &Vec<F>, val_2: &Vec<F>) -> F {
    val_1
        .iter()
        .zip(val_2.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::ZERO, |acc, x| acc + x)
}

pub fn prover_step(
    commitments: [G1Affine; 3],
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    u: &F,
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
    q_vec: &mut Vec<G1Affine>,
) -> (
    (G1Affine, G1Affine, G1Affine),
    (Vec<F>, Vec<F>),
    (Vec<G1Affine>, Vec<G1Affine>, Vec<G1Affine>)
) {
    let [_a, _l, _r] = commitments;

    let _p =
        ((_l * (u * u)) + _a + _r * (u.inverse().unwrap() * u.inverse().unwrap())).into_affine();

    let g_prime = fold_group(g_vec, &u.inverse().unwrap());

    let h_prime = fold_group(h_vec, &u);

    let q_prime: Vec<G1Affine> = q_vec.chunks(2).map(|chunk| chunk[0]).collect();

    let a_prime = fold_field(a, &u);
    let b_prime = fold_field(b, &u.inverse().unwrap());

    let mut new_vec = [&a_prime[..], &a_prime[..], &b_prime[..]].concat();

    let mut new_ec_points = [&g_prime[..], &h_prime[..], &q_prime[..]].concat();

    let (l, r) = compute_secondary_diagonal(&mut new_ec_points, &mut new_vec);

    (
        (_p, l, r),
        (a_prime, b_prime),
        (g_prime, h_prime, q_prime)
    )
}

pub fn verifier_step(
    commitments: [G1Affine; 3],
    u: &F,
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
) -> (G1Affine, Vec<G1Affine>, Vec<G1Affine>) {
    let [_a, _l, _r] = commitments;

    let _p =
        ((_l * (u * u)) + _a + _r * (u.inverse().unwrap() * u.inverse().unwrap())).into_affine();

    let g_prime = fold_group(g_vec, &u.inverse().unwrap());

    let h_prime = fold_group(h_vec, &u);

    (_p, g_prime, h_prime)
}

pub fn log_ipa(
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
    q_vec: &mut Vec<G1Affine>,
) {
    assert!(a.len() == b.len(), "Need to be same length");

    if a.len() < 2 ^ 8 {
        a.push(F::ZERO);
        b.push(F::ZERO);
    }

    let mut primary_vec = [&a[..], &a[..], &b[..]].concat();
    let mut ec_points_vector = [&g_vec[..], &h_vec[..], &q_vec[..]].concat();

    let _a = commit(&primary_vec, &ec_points_vector).unwrap();
    let (_l, _r) = compute_secondary_diagonal(g_vec, &mut primary_vec);
}
