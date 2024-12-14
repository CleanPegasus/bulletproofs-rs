mod test {
    use ark_bls12_381::{Bls12_381, Fq, Fr as F};
    use ark_ff::{Field, UniformRand};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use bulletproofs_rs::{
        pedersen_commitment::generate_n_random_points,
        vector_polynomial::{Coeff, VectorPolynomial},
        zk_ipa::{committment_vector_polynomials, verify_ipa},
        zk_mul::{commit_polynomials, generate_proof, generate_random_field_element, verify_proof},
    };
    use rand::Rng;

    #[test]
    fn test_polynomial_committments() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);
        let h_vec = generate_n_random_points("bulletproof".into(), 3);

        let g = generate_n_random_points("ios".to_string(), 1)[0];
        let h = generate_n_random_points("seed".to_string(), 1)[0];

        let a = Coeff::random(3);
        let s_l = Coeff::random(3);
        let l_x = VectorPolynomial::new(vec![a, s_l]);

        let b = Coeff::random(3);
        let s_r = Coeff::random(3);
        let r_x = VectorPolynomial::new(vec![b, s_r]);

        let (committments, blinding_factors) =
            committment_vector_polynomials(l_x, r_x, &g_vec, &h_vec, &g, &h);
    }

    #[test]
    fn test_generate_proof() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);
        let h_vec = generate_n_random_points("bulletproof".into(), 3);

        let g = generate_n_random_points("ios".to_string(), 1)[0];
        let h = generate_n_random_points("seed".to_string(), 1)[0];

        let a = Coeff::random(3);
        let s_l = Coeff::random(3);
        let l_x = VectorPolynomial::new(vec![a, s_l]);

        let b = Coeff::random(3);
        let s_r = Coeff::random(3);
        let r_x = VectorPolynomial::new(vec![b, s_r]);

        let t_x = l_x.clone() * r_x.clone();

        let (committments, blinding_factors) =
            committment_vector_polynomials(l_x.clone(), r_x.clone(), &g_vec, &h_vec, &g, &h);

        let u = generate_random_field_element();

        let l_u = l_x.evaluate(&u);
        let r_u = r_x.evaluate(&u);

        let t_u = t_x.evaluate(&u);

        let proof = generate_proof(&blinding_factors, &u);
    }

    #[test]
    fn test_verification() {
        let g_vec = generate_n_random_points("hello".to_string(), 3);
        let h_vec = generate_n_random_points("bulletproof".into(), 3);

        let g = generate_n_random_points("ios".to_string(), 1)[0];
        let h = generate_n_random_points("seed".to_string(), 1)[0];

        let a = Coeff::random(3);
        let s_l = Coeff::random(3);
        let l_x = VectorPolynomial::new(vec![a, s_l]);

        let b = Coeff::random(3);
        let s_r = Coeff::random(3);
        let r_x = VectorPolynomial::new(vec![b, s_r]);

        let t_x = l_x.clone() * r_x.clone();

        let (committments, blinding_factors) =
            committment_vector_polynomials(l_x.clone(), r_x.clone(), &g_vec, &h_vec, &g, &h);

        let u = generate_random_field_element();

        let l_u = l_x.evaluate(&u);
        let r_u = r_x.evaluate(&u);

        let t_u = t_x.evaluate(&u);

        let proofs = generate_proof(&blinding_factors, &u);

        let verification = verify_ipa(
            l_u,
            r_u,
            &t_u,
            &u,
            &committments,
            &proofs,
            g_vec,
            h_vec,
            &g,
            &h,
        );

        assert!(verification);
    }
}
