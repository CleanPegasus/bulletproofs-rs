use crate::random_ec_points::{generate_n_random_points, generate_random_field_element};

use super::succinct_proof::{commit, compute_secondary_diagonal, fold_field, fold_group};

use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};

pub fn inner_product(val_1: &Vec<F>, val_2: &Vec<F>) -> F {
    assert!(val_1.len() == val_2.len());
    val_1
        .iter()
        .zip(val_2.iter())
        .map(|(a, b)| *a * *b)
        .fold(F::ZERO, |acc, x| acc + x)
}

pub fn hadamard_product(field_elements: &Vec<F>, ec_points: &Vec<G1Affine>) -> Vec<G1Affine> {
    assert!(field_elements.len() == ec_points.len());

    let result: Vec<G1Affine> = field_elements
        .iter()
        .zip(ec_points.iter())
        .map(|(element, ec_point)| (*ec_point * element).into_affine())
        .collect();
    result
}

pub fn prover_step(
    commitments: [G1Affine; 3],
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    u: &F,
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
    q: &G1Affine,
) -> (
    (G1Affine, G1Affine, G1Affine),
    (Vec<F>, Vec<F>),
    (Vec<G1Affine>, Vec<G1Affine>),
) {
    let [_a, _l, _r] = commitments;

    let _p =
        ((_l * (u * u)) + _a + _r * (u.inverse().unwrap() * u.inverse().unwrap())).into_affine();

    let g_prime = fold_group(g_vec, &u.inverse().unwrap());

    let h_prime = fold_group(h_vec, &u);

    let a_prime = fold_field(a, &u);
    let b_prime = fold_field(b, &u.inverse().unwrap());

    let mut new_vec = [&a_prime[..], &a_prime[..], &b_prime[..]].concat();

    let mut q_n = hadamard_product(&b_prime,  &vec![*q; a_prime.len()]);

    let mut new_ec_points = [&g_prime[..], &q_n[..], &h_prime[..]].concat();

    dbg!(&new_ec_points.len());
    dbg!(&new_vec.len());

    let (l, r) = compute_secondary_diagonal(&mut new_ec_points, &mut new_vec);

    ((_p, l, r), (a_prime, b_prime), (g_prime, h_prime))
}

pub fn verifier_step(
    commitments: [G1Affine; 3],
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
) -> (G1Affine, F, Vec<G1Affine>, Vec<G1Affine>) {
    let [_a, _l, _r] = commitments;

    let u = generate_random_field_element();

    let _p =
        ((_l * (u * u)) + _a + _r * (u.inverse().unwrap() * u.inverse().unwrap())).into_affine();

    let g_prime = fold_group(g_vec, &u.inverse().unwrap());

    let h_prime = fold_group(h_vec, &u);

    (_p, u, g_prime, h_prime)
}

pub fn log_ipa(
    a: &mut Vec<F>,
    b: &mut Vec<F>,
    g_vec: &mut Vec<G1Affine>,
    h_vec: &mut Vec<G1Affine>,
    q: &G1Affine,
) -> bool {
    assert!(a.len() == b.len(), "Need to be same length");

    let mut count = 0;

    while a.len() < 2u32.pow(4) as usize {
        a.push(F::ZERO);
        b.push(F::ZERO);
        g_vec.push(G1Affine::zero());
        h_vec.push(G1Affine::zero());
    }

    dbg!(&a.len());

    let mut primary_vec = [&a[..], &a[..], &b[..]].concat();
    let mut q_n = hadamard_product(b,  &vec![*q; a.len()]);
    let mut ec_points_vector = [&g_vec[..], &q_n[..], &h_vec[..]].concat();

    dbg!(&primary_vec.len());
    dbg!(&ec_points_vector.len());
    dbg!(&a.len());

    dbg!(&q_n.len());
    dbg!(&h_vec.len());
    dbg!(&g_vec.len());

    let mut _a = commit(&primary_vec, &ec_points_vector).unwrap();
    let (mut _l, mut _r) = compute_secondary_diagonal(&mut ec_points_vector, &mut primary_vec);

    let commitments = [_a, _l, _r];
    while a.len() > 0 {
        if a.len() > 1 {
            let (_p, u, _, _) = verifier_step(commitments, g_vec, h_vec);

            ((_a, _l, _r), (*a, *b), (*g_vec, *h_vec)) =
                prover_step(commitments, a, b, &u, g_vec, h_vec, q);
        } else {
            return _a == g_vec[0] * a[0] + h_vec[0] * b[0] + *q * inner_product(a, b);
        }

        count += 1;
        println!("Ran loop {} times", count);
    }

    return false;
}

#[test]
fn test_log_ipa() {
    let mut a = vec![F::from(2), F::from(3), F::from(4), F::from(12)];
    let mut b = vec![F::from(5), F::from(4), F::from(9), F::from(18)];

    let mut g_vec = generate_n_random_points("hello".to_string(), 4);
    let mut h_vec = generate_n_random_points("bullet".to_string(), 4);
    let q = generate_n_random_points("proof".to_string(), 1)[0];

    let verification = log_ipa(&mut a, &mut b, &mut g_vec, &mut h_vec, &q);

    dbg!(verification);
}
