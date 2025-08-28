use crate::{decompress_point, biased_hash_to_point};

#[test]
fn test_vectors() {
  // tests.txt file copied from monero repo
  // https://github.com/monero-project/monero/
  //   blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/tests/crypto/tests.txt
  let reader = include_str!("./tests.txt");

  for line in reader.lines() {
    let mut words = line.split_whitespace();
    let command = words.next().unwrap();

    match command {
      "check_key" => {
        let key = words.next().unwrap();
        let expected = match words.next().unwrap() {
          "true" => true,
          "false" => false,
          _ => unreachable!("invalid result"),
        };

        let actual = decompress_point(hex::decode(key).unwrap().try_into().unwrap());
        assert_eq!(actual.is_some(), expected);
      }
      "hash_to_ec" => {
        let bytes = words.next().unwrap();
        let expected = words.next().unwrap();

        let actual = biased_hash_to_point(hex::decode(bytes).unwrap().try_into().unwrap());
        assert_eq!(hex::encode(actual.compress().to_bytes()), expected);
      }
      _ => unreachable!("unknown command"),
    }
  }
}

#[test]
fn single_and_multithreaded_generators() {
  use helioselene::Helios;
  use crate::{FCMP_HELIOS_GENERATORS, FcmpGenerators};

  let single = FcmpGenerators::<Helios>::new_internal_singlethreaded(FCMP_HELIOS_GENERATORS);
  let multi = FcmpGenerators::<Helios>::new_internal_multithreaded(FCMP_HELIOS_GENERATORS).unwrap();
  assert_eq!(single.generators.g(), multi.generators.g());
  assert_eq!(single.generators.h(), multi.generators.h());
  assert_eq!(single.generators.g_bold_slice(), multi.generators.g_bold_slice());
  assert_eq!(single.generators.h_bold_slice(), multi.generators.h_bold_slice());
}
