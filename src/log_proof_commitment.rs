use std::error::Error;

use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField};

use crate::{
    random_ec_points::generate_random_field_element,
    succinct_proof::{commit, fold_field, fold_group},
};

use super::succinct_proof::{commit_vector, verify_succinct_proof};

pub fn verify_log_proof_of_committment(
    commiting_vector: &mut Vec<F>,
    g_vec: &mut Vec<G1Affine>,
) -> bool {
    if commiting_vector.len() < 2_i32.pow(4) as usize {
        commiting_vector.push(F::ZERO);
        g_vec.push(G1Affine::zero())
    }

    let mut a = commiting_vector.clone();
    let mut g = g_vec.clone();

    while a.len() > 0 {
        let mut a_vec: Vec<F> = vec![F::ZERO];
        let mut g_vec_last: Vec<G1Affine> = vec![G1Affine::zero()];

        if a.len() > 1 {
            let (_a, _l, _r) = commit_vector(&mut a.clone(), &mut g.clone());

            let u = generate_random_field_element();

            a = fold_field(&mut a.clone(), &u);

            if !verify_succinct_proof(&(_a, _l, _r), &a, &u, &mut g) {
                println!("Verification Failed");
                break;
            }

            g = fold_group(&mut g, &u.inverse().unwrap());

            a_vec = a.clone();
            g_vec_last = g.clone();
        } else {
            let _a = commit(&a_vec, &g_vec_last).unwrap();
            return _a == g_vec_last[0] * a_vec[0];
        }
    }

    return false;
}
