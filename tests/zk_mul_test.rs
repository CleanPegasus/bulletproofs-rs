mod test {
    use ark_bls12_381::{Bls12_381, Fq, Fr as F};
    use ark_ff::{Field, UniformRand};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use bulletproofs_rs::{
        pedersen_commitment::generate_n_random_points,
        zk_mul::{commit_polynomials, generate_proof, verify_proof},
    };
    use rand::Rng;

    #[test]
    fn test_polynomial_committment() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);

        let coeffs_l = [F::from(1), F::from(2)];
        let l_x = DensePolynomial::from_coefficients_slice(&coeffs_l);

        let coeffs_r = [F::from(3), F::from(4)];
        let r_x = DensePolynomial::from_coefficients_slice(&coeffs_r);

        let (committment, blinding_factors) = commit_polynomials(&l_x, &r_x, &g_vec);

        dbg!(committment);
    }

    #[test]
    fn test_generate_proof() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);

        let coeffs_l = [F::from(1), F::from(2)];
        let l_x = DensePolynomial::from_coefficients_slice(&coeffs_l);

        let coeffs_r = [F::from(3), F::from(4)];
        let r_x = DensePolynomial::from_coefficients_slice(&coeffs_r);

        let (committment, blinding_factors) = commit_polynomials(&l_x, &r_x, &g_vec);

        let mut rng = rand::thread_rng();
        let random_u = rng.gen_range(1..10000000);
        let u = F::from(random_u);

        let proof = generate_proof(&blinding_factors, &u);

        dbg!(proof);
    }

    #[test]
    fn test_verification() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);

        let coeffs_l = [F::from(1), F::from(2)];
        let l_x = DensePolynomial::from_coefficients_slice(&coeffs_l);

        let coeffs_r = [F::from(3), F::from(4)];
        let r_x = DensePolynomial::from_coefficients_slice(&coeffs_r);

        let t_x = &l_x * &r_x;

        let (committments, blinding_factors) = commit_polynomials(&l_x, &r_x, &g_vec);

        let mut rng = rand::thread_rng();
        let random_u = rng.gen_range(1..10000000);
        let u = F::from(random_u);

        let proofs = generate_proof(&blinding_factors, &u);

        let l_u = l_x.evaluate(&u);
        let r_u = r_x.evaluate(&u);
        let t_u = t_x.evaluate(&u);

        let poly_evaluations = (l_u, r_u, t_u);

        let verification = verify_proof(&committments, &g_vec, &proofs, &u, &poly_evaluations);

        dbg!(&verification);
        assert!(verification)
    }
}
