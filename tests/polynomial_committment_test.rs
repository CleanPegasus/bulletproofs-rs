mod test {
  use ark_bls12_381::{Bls12_381, Fq, Fr as F};
  use ark_ff::UniformRand;
  use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use bulletproofs_rs::{pedersen_commitment::generate_n_random_points, polynomial_commitment::{commit_polynomial, generate_proof, verify}};


  #[test]
  fn test_commit_polyomial() {
    let g = generate_n_random_points("hello".into(), 1)[0];
    let b = generate_n_random_points("hello".into(), 1)[0];

    let coeffs = [10, 20, 30, 40];
    let coeffs_f = coeffs.map(|coeff| F::from(coeff));

    let poly = DensePolynomial::from_coefficients_slice(&coeffs_f);
    
    let mut rng = ark_std::test_rng();
    let gammas: Vec<F> = (0..coeffs.len()).map(|_| F::rand(&mut rng)).collect();

    let committments = commit_polynomial(&poly, &gammas, &g, &b);

    println!("{:?}", committments);

  }

  #[test]
  fn test_generate_proof() {
    let g = generate_n_random_points("hello".into(), 1)[0];
    let b = generate_n_random_points("hello".into(), 1)[0];

    let coeffs = [10, 20, 30, 40];
    let coeffs_f = coeffs.map(|coeff| F::from(coeff));

    let poly = DensePolynomial::from_coefficients_slice(&coeffs_f);
    
    let mut rng = ark_std::test_rng();
    let gammas: Vec<F> = (0..coeffs.len()).map(|_| F::rand(&mut rng)).collect();

    let committments = commit_polynomial(&poly, &gammas, &g, &b);

    let u = F::rand(&mut rng);
    let proof = generate_proof(&gammas, &u);

    println!("{}", proof);
  }

  #[test]
  fn test_verify() {
    let g = generate_n_random_points("hello".into(), 1)[0];
    let b = generate_n_random_points("hello".into(), 1)[0];

    let coeffs = [10, 20, 30, 40];
    let coeffs_f = coeffs.map(|coeff| F::from(coeff));

    let poly = DensePolynomial::from_coefficients_slice(&coeffs_f);
    dbg!(&poly);
    let mut rng = ark_std::test_rng();
    let gammas: Vec<F> = (0..coeffs.len()).map(|_| F::rand(&mut rng)).collect();

    let committments = commit_polynomial(&poly, &gammas, &g, &b).unwrap();

    let u = F::rand(&mut rng);
    let proof = generate_proof(&gammas, &u);

    let f_u = poly.evaluate(&u);
    let verification = verify(&committments, &g, &b, &u, &f_u, &proof);

    assert!(verification);
  }
}
