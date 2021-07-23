use sgx_tstd::{char, vec::Vec};
use sgx_types::*;

fn decode_hex_digit(digit: char) -> u8 {
    match digit {
        '0'..='9' => digit as u8 - '0' as u8,
        'a'..='f' => digit as u8 - 'a' as u8 + 10,
        'A'..='F' => digit as u8 - 'A' as u8 + 10,
        _ => panic!(),
    }
}

pub fn decode_spid(hex: &str) -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let hex = hex.trim();

    if hex.len() < 16 * 2 {
        println!("Input spid file len ({}) is incorrect!", hex.len());
        return spid;
    }

    let decoded_vec = decode(hex);

    spid.id.copy_from_slice(&decoded_vec[..16]);

    spid
}

pub fn decode(hex: &str) -> Vec<u8> {
    let mut r: Vec<u8> = Vec::new();
    let mut chars = hex.chars().enumerate();
    loop {
        let (pos, first) = match chars.next() {
            None => break,
            Some(elt) => elt,
        };
        if first == ' ' {
            continue;
        }
        let (_, second) = match chars.next() {
            None => panic!("pos = {}d", pos),
            Some(elt) => elt,
        };
        r.push((decode_hex_digit(first) << 4) | decode_hex_digit(second));
    }
    r
}

#[cfg(test)]
mod test {

    use super::decode;

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode(""), [].to_vec());
        assert_eq!(decode("00"), [0x00u8].to_vec());
        assert_eq!(decode("ff"), [0xffu8].to_vec());
        assert_eq!(decode("AB"), [0xabu8].to_vec());
        assert_eq!(decode("fa 19"), [0xfau8, 0x19].to_vec());
    }
}
