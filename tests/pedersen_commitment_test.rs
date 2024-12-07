mod test {
  use bulletproofs_rs::pedersen_commitment::generate_n_random_points;
pub use bulletproofs_rs::pedersen_commitment::{generate_random_point};

  #[test]
  fn test_generate_random_point() {
    let (point, _) = generate_random_point("hello".to_string());
    assert!(point.is_on_curve());
  }

  #[test]
  fn test_generate_n_points() {
    let points = generate_n_random_points("hello".to_string(), 10);
    for point in points {
      assert!(point.is_on_curve())
    }
  }

}