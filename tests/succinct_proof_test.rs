mod test {
    use ark_bn254::{Fq, Fr as F, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, BigInt, Field, UniformRand};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::rand::thread_rng;
    use bulletproofs_rs::random_ec_points::{
        generate_n_random_points, generate_random_field_element,
    };
    use bulletproofs_rs::{
        pedersen_commitment::commit,
        succinct_proof::{commit_vector, fold_field, fold_group, verify_succinct_proof},
        vector_polynomial::{Coeff, VectorPolynomial},
        zk_ipa::{committment_vector_polynomials, verify_ipa},
        zk_mul::{commit_polynomials, generate_proof, verify_proof},
    };
    use rand::Rng;

    #[test]
    fn test_vector_committments() {
        let mut g_vec = generate_n_random_points("hello".to_string(), 2);

        let mut a = vec![F::from(2), F::from(3)];
        let committments = commit_vector(&mut a, &mut g_vec);

        let (_a, _l, _r) = committments;

        assert!(_a == g_vec[0] * a[0] + g_vec[1] * a[1]);

        assert!(_l == g_vec[1] * a[0]);

        assert!(_r == g_vec[0] * a[1]);
    }

    #[test]
    fn test_fold_field() {
        let mut rng = thread_rng();
        let u = F::rand(&mut rng);

        // Create a vector of random field elements (odd length to test padding)
        let mut input = vec![F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng)];
        let original_input = input.clone();

        let result = fold_field(&mut input, &u);

        // Check length is (original_length + 1) / 2
        assert_eq!(result.len(), 2);

        // Verify first folded element
        let expected_first = original_input[0] * u + original_input[1] * u.inverse().unwrap();
        assert_eq!(result[0], expected_first);

        // Verify second folded element (with padding)
        let expected_second = original_input[2] * u + F::ZERO * u.inverse().unwrap();
        assert_eq!(result[1], expected_second);
    }

    #[test]
    fn test_fold_group() {
        let mut rng = thread_rng();
        let u = F::rand(&mut rng);

        // Create random group elements (odd length to test padding)
        let g = G1Affine::generator();
        let mut input = vec![
            (g * F::rand(&mut rng)).into_affine(),
            (g * F::rand(&mut rng)).into_affine(),
            (g * F::rand(&mut rng)).into_affine(),
        ];
        let original_input = input.clone();

        let result = fold_group(&mut input, &u);

        // Check length is (original_length + 1) / 2
        assert_eq!(result.len(), 2);

        // Verify first folded element
        let expected_first =
            (original_input[0] * u + original_input[1] * u.inverse().unwrap()).into_affine();
        assert_eq!(result[0], expected_first);

        // Verify second folded element (with padding)
        let expected_second =
            (original_input[2] * u + G1Affine::zero() * u.inverse().unwrap()).into_affine();
        assert_eq!(result[1], expected_second);
    }

    #[test]
    fn test_generate_proof() {
        let mut g_vec = generate_n_random_points("hello".to_string(), 2);

        let mut a = vec![F::from(2), F::from(3)];
        let committments = commit_vector(&mut a, &mut g_vec);

        let u = generate_random_field_element();
        let proof = fold_field(&mut a, &u);

        let a_prime = a[0] * u + a[1] * u.inverse().unwrap();

        assert!(proof[0] == a_prime)
    }

    #[test]
    fn test_verification() {
        let mut g_vec = generate_n_random_points("hello".to_string(), 2);
        let mut a_vec = vec![F::from(2), F::from(5)];

        let mut a_copy = a_vec.clone();
        let mut g_vec_copy = g_vec.clone();

        let committments = commit_vector(&mut a_vec, &mut g_vec);
        let u = F::from(3);
        dbg!(&a_copy);
        let proof = fold_field(&mut a_copy, &u);

        let a_prime = a_vec[0] * u + a_vec[1] * u.inverse().unwrap();

        assert!(proof[0] == a_prime);

        let (a, l, r) = committments;

        assert!(l == g_vec[1] * a_vec[0]);

        let l_u_sqr = l.clone() * u * u;
        let l_u_sqr_verify = g_vec[1] * a_vec[0] * u * u;

        assert!(l_u_sqr == l_u_sqr_verify);

        let u_inv = u.inverse().unwrap();

        // First verify that r equals g_vec[0] * a_vec[1]
        // Equation: r = g₀ * a₁
        let g_times_a = (g_vec[0] * a_vec[1]).into_affine(); // Convert to affine immediately
        assert!(r == g_times_a);

        // Calculate u⁻² (inverse of u squared)
        let scalar = u_inv * u_inv;

        // Equation: r_u_sqr_inv = r * u⁻²
        let r_u_sqr_inv = (r * scalar).into_affine();

        // Equation: r_u_sqr_inv_verify = (g₀ * a₁) * u⁻²
        let r_u_sqr_inv_verify = (g_times_a * scalar).into_affine();

        assert!(r_u_sqr_inv == r_u_sqr_inv_verify);

        // Equation: rhs = L*u² + A + R*u⁻²
        let rhs = ((l + a).into_affine() + r).into_affine();

        // Equation: g'₀ = g₀*u⁻¹ + g₁*u
        let folded_g = fold_group(&mut g_vec, &u_inv);
        assert!(folded_g[0] == g_vec[0] * u_inv + g_vec[1] * u);

        // Equation: lhs = g'₀ * a'₀
        // where a'₀ = a₀*u + a₁*u⁻¹
        // where g'₀ = g₀*u⁻¹ + g₁*u

        let lhs = (folded_g[0] * proof[0]).into_affine();

        // assert!(proof_commit == lhs);

        let verification = verify_succinct_proof(&committments, &proof, &u, &mut g_vec);

        assert!(verification);

        // assert!(lhs == rhs)
    }

    #[test]
    fn test_verification_new() {
        let mut g_vec = generate_n_random_points("hello".to_string(), 2);
        let mut a_vec = vec![F::from(2), F::from(5)];

        let mut a_copy = a_vec.clone();

        let committments = commit_vector(&mut a_vec, &mut g_vec);
        let u = F::from(3);

        let proof = fold_field(&mut a_copy, &u);

        let verification = verify_succinct_proof(&committments, &proof, &u, &mut g_vec);

        assert!(verification)
    }

    #[test]
    fn test_manual_verification() {
        let mut g_vec = generate_n_random_points("hello".to_string(), 2);
        let mut a_vec = vec![F::from(2), F::from(5)];

        let a_bigint: BigInt<4> = a_vec[0].into();

        let a_committ = (g_vec[0] * a_vec[0] + g_vec[1] * a_vec[1]).into_affine();
        let l_committ = (g_vec[1] * a_vec[0]).into_affine();
        let r_committ = (g_vec[0] * a_vec[1]).into_affine();

        let (_a, _l, _r) = commit_vector(&mut a_vec, &mut g_vec);

        assert!(a_committ == _a);
        assert!(l_committ == _l);
        assert!(r_committ == _r);

        let u = F::from(2);
        let u_inv = u.inverse().unwrap();
        let proof = a_vec[0] * u + a_vec[1] * u_inv;

        let l_u_sqr = (_r * u * u).into_affine();

        let r_u_inv_sqr = (_l * u_inv * u_inv).into_affine();

        let folded_g =
            ((g_vec[0] * u_inv).into_affine() + (g_vec[1] * u).into_affine()).into_affine();

        let lhs = (l_u_sqr + _a + r_u_inv_sqr).into_affine();

        let rhs = (folded_g * proof).into_affine();

        assert!(lhs == rhs);
    }

    #[test]
    fn test_generate_random_ex_point() {
        let ec_points = generate_n_random_points("hello".to_string(), 2);

        dbg!(&ec_points);

        let u = 2;
        let a = F::from(100);

        ec_points[0] * F::from(u);
    }
}
