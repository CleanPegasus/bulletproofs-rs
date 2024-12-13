#[cfg(test)]
mod test {
    use ark_bls12_381::Fr as F;
    use ark_ff::{AdditiveGroup, Field};
    use bulletproofs_rs::vector_polynomial::{Coeff, VectorPolynomial};

    #[test]
    fn test_coeff_zero() {
        let zero_coeff = Coeff::zero(3);
        assert_eq!(zero_coeff.0.len(), 3);
        assert!(zero_coeff.0.iter().all(|x| x.eq(&F::ZERO)));
    }

    #[test]
    fn test_coeff_addition() {
        let a = Coeff(vec![F::from(1u64), F::from(2u64), F::from(3u64)]);
        let b = Coeff(vec![F::from(4u64), F::from(5u64), F::from(6u64)]);
        let sum = a.clone() + b;
        assert_eq!(sum.0, vec![F::from(5u64), F::from(7u64), F::from(9u64)]);
    }

    #[test]
    fn test_coeff_multiplication() {
        let a = Coeff(vec![F::from(1u64), F::from(2u64), F::from(3u64)]);
        let b = Coeff(vec![F::from(4u64), F::from(5u64), F::from(6u64)]);
        let product = a.clone() * b;
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(product, F::from(32u64));
    }

    #[test]
    fn test_vector_polynomial_creation() {
        let coeffs = vec![
            Coeff(vec![F::from(1u64), F::from(2u64)]),
            Coeff(vec![F::from(3u64), F::from(4u64)]),
        ];
        let poly = VectorPolynomial::new(coeffs);
        assert_eq!(poly.coeffs.len(), 2);
    }

    #[test]
    #[should_panic(expected = "All coefficient vectors must have the same length")]
    fn test_vector_polynomial_invalid_creation() {
        let coeffs = vec![
            Coeff(vec![F::from(1u64), F::from(2u64)]),
            Coeff(vec![F::from(3u64)]),
        ];
        VectorPolynomial::new(coeffs);
    }

    #[test]
    fn test_vector_polynomial_evaluation() {
        let coeffs = vec![
            Coeff(vec![F::from(1u64), F::from(2u64)]), // constant term
            Coeff(vec![F::from(3u64), F::from(4u64)]), // x term
        ];
        let poly = VectorPolynomial::new(coeffs);
        let x = F::from(2u64);
        let result = poly.evaluate(&x);
        // At x = 2:
        // First component: 1 + 3*2 = 7
        // Second component: 2 + 4*2 = 10
        assert_eq!(result.0, vec![F::from(7u64), F::from(10u64)]);
    }

    #[test]
    fn test_vector_polynomial_display() {
        let coeffs = vec![
            Coeff(vec![F::from(1u64), F::from(2u64)]),
            Coeff(vec![F::from(3u64), F::from(4u64)]),
        ];
        let poly = VectorPolynomial::new(coeffs);
        let display = format!("{}", poly);
        assert_eq!(display, "(1, 2)x^0 + (3, 4)x^1");
    }
}
