mod test {
    use ark_bls12_381::{Bls12_381, Fq, Fr as F};
    use ark_ff::UniformRand;
    use bulletproofs_rs::pedersen_commitment::{generate_n_random_points, pedersen_commitment};


    #[test]
    fn test_generate_n_points() {
        let points = generate_n_random_points("hello".to_string(), 10);
        for point in points {
            assert!(point.is_on_curve())
        }
    }

    #[test]
    fn test_pedersen_committment() {
        let mut rng = ark_std::test_rng();
        let vector = [1, 2, 3, 4, 5];
        let field_element_vector: Vec<F> = vector.into_iter().map(|val| F::from(val)).collect();
        let g_vec =
            generate_n_random_points("hello".to_string(), (field_element_vector.len() + 1) as i32);
        let blinding_factor = F::rand(&mut rng);
        let committment = pedersen_commitment(&field_element_vector, &g_vec, blinding_factor);
        dbg!(&committment);
        assert!(committment.is_ok())
    }
}
