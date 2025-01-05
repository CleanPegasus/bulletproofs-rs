
use ark_bn254::{Fr as F, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, Field};

use crate::{random_ec_points::generate_random_field_element};


pub fn log_ipa_proof(
    a: Vec<F>,
    b: Vec<F>,
    g_vec: Vec<G1Affine>,
    h_vec: Vec<G1Affine>,
    q: G1Affine
) -> bool {

    let initial_inner_product = compute_inner_product(&a, &b);
    println!("Initial inner product: {:?}", initial_inner_product);

    let mut q_vec = hadamard_product(&b, &vec![q.clone(); b.len()]);

    let mut p_com = (commit(&a, &g_vec) + commit(&b, &h_vec) + commit(&a, &q_vec)).into_affine();
    println!("Initial p_com: {:?}", p_com);

    let mut a_prime = a.clone();
    let mut b_prime = b.clone();
    
    let mut g_prime = g_vec.clone();
    let mut h_prime = h_vec.clone();

    while a_prime.len() > 0{

        if a_prime.len() == 1 {
            let final_inner_product = a_prime[0] * b_prime[0];
            println!("Final inner product: {:?}", final_inner_product);
            println!("Inner products match: {}", initial_inner_product == final_inner_product);

            let final_result = commit(&a_prime, &g_prime) + commit(&b_prime, &h_prime) + (q * (a_prime[0] * b_prime[0]));
            println!("Final comparison:");
            println!("p_com: {:?}", p_com);
            println!("final_result: {:?}", final_result.into_affine());
            return p_com == final_result.into_affine();
        } else {

            let current_inner_product = compute_inner_product(&a_prime, &b_prime);
            println!("Current inner product: {:?}", current_inner_product);

            let q_vec = hadamard_product(&b_prime, &vec![q.clone(); b_prime.len()]);

            let (l_com, r_com) = compute_l_r(a_prime.clone(), b_prime.clone(), g_prime.clone(), h_prime.clone(), q_vec.clone());

            let u = generate_random_field_element();
            println!("Generated u: {:?}", u);

            // Verifier and prover both compute p_prime, g_prime and h_prime
            let old_p_com = p_com.clone();
            p_com = (l_com * u * u + p_com + r_com * u.inverse().unwrap() * u.inverse().unwrap()).into_affine();
            println!("Updated p_com from {:?} to {:?}", old_p_com, p_com);

            g_prime = fold_points(g_prime.clone(), &u.inverse().unwrap());
            h_prime = fold_points(h_prime.clone(), &u);

            // prover computes a_prime and b_prime
            let old_len = a_prime.len();
            a_prime = fold_field(a_prime.clone(), &u);
            b_prime = fold_field(b_prime.clone(), &u.inverse().unwrap());
            println!("Vector lengths after folding: {} -> {}", old_len, a_prime.len());

        }
    }
    return false
}


pub fn compute_l_r(a: Vec<F>, b: Vec<F>, ec_points_g: Vec<G1Affine>, ec_points_h: Vec<G1Affine>, ec_points_q: Vec<G1Affine>) -> (G1Affine, G1Affine) {
    let (l1_com, r1_com) = compute_secondary_diagonal(a.clone(), ec_points_g.clone());
    let (l2_com, r2_com) = compute_secondary_diagonal(b.clone(), ec_points_h.clone());
    let (l3_com, r3_com) = compute_secondary_diagonal(a.clone(), ec_points_q.clone());

    let l_com = (l1_com + l2_com + l3_com).into_affine();
    let r_com = (r1_com + r2_com + r3_com).into_affine();

    (l_com, r_com)

}

pub fn compute_secondary_diagonal(mut a: Vec<F>, mut ec_points: Vec<G1Affine>) -> (G1Affine, G1Affine) {

    
    let l: Vec<F> = a.chunks(2).map(|chunk| chunk[0]).collect();
    let r: Vec<F> = a.chunks(2).map(|chunk| chunk[1]).collect();

    let g1_vec: Vec<G1Affine> = ec_points.chunks(2).map(|chunk| chunk[0]).collect();
    let g2_vec: Vec<G1Affine> = ec_points.chunks(2).map(|chunk| chunk[1]).collect();
    
    let l_com = commit(&l, &g2_vec);
    let r_com = commit(&r, &g1_vec);

    (l_com, r_com)

}

/// Computes the commitment C which is the sum of each generator g_i multiplied by the corresponding scalar a_i
pub fn commit(
    committing_vector: &Vec<F>,
    g_vec: &Vec<G1Affine>,
) -> G1Affine {
    assert!(committing_vector.len() == g_vec.len(), "Invalid vector lengths");
    let mut result: G1Affine = G1Affine::zero();
    for (index, point) in committing_vector.iter().enumerate() {
        // C += g_i * a_i
        result = (result + g_vec[index] * point).into_affine();
    }
    result
}

pub fn hadamard_product(a_vec: &Vec<F>, g_vec: &Vec<G1Affine>) -> Vec<G1Affine> {
    assert!(a_vec.len() == g_vec.len(), "Invalid vector lengths");
    a_vec.iter().zip(g_vec.iter()).map(|(&a, &g)| (g * a).into_affine()).collect()
}

pub fn fold_points(g_vec: Vec<G1Affine>, u: &F) -> Vec<G1Affine> {
    let u_inv = u.inverse().unwrap();
    g_vec.chunks(2).map(|chunk| (chunk[0] * u + chunk[1] * u_inv).into_affine()).collect()
}

pub fn fold_field(a_vec: Vec<F>, u: &F) -> Vec<F> {
    let u_inv = u.inverse().unwrap();
    a_vec.chunks(2).map(|chunk| chunk[0] * u + chunk[1] * u_inv).collect()
}

fn compute_inner_product(a: &Vec<F>, b: &Vec<F>) -> F {
    a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum()
}