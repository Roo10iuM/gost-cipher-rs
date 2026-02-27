pub struct Magma {
    key: [u32; 8],
}

impl Magma {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            key: from_u8_32_to_u32_8(key),
        }
    }

    pub fn encrypt<B: Into<Vec<u8>>>(&self, plaintext: B) -> Vec<u8> {
        let mut bytes = plaintext.into();
        self.padding(&mut bytes);
        for i in 0..(bytes.len() / 8) {
            let block: [u8; 8] = bytes[(i * 8)..((i + 1) * 8)]
                .try_into()
                .expect("Unreachable");
            let (mut a1, mut a0) = from_u8_8_to_u32u32(&block);

            for round in 0..31 {
                (a1, a0) = self.G(self.get_round_key(round), a1, a0);
            }
            (a1, a0) = self.GnT(self.key[0], a1, a0);

            for j in 0..4 {
                bytes[i * 8 + j] = ((a1 >> ((3 - j) * 8)) & 0xFF) as u8;
            }
            for j in 0..4 {
                bytes[i * 8 + 4 + j] = ((a0 >> ((3 - j) * 8)) & 0xFF) as u8;
            }
        }
        bytes
    }

    pub fn decrypt<B: Into<Vec<u8>>>(&self, ciphertext: B) -> Vec<u8> {
        let mut bytes = ciphertext.into();
        for i in 0..(bytes.len() / 8) {
            let block: [u8; 8] = bytes[(i * 8)..((i + 1) * 8)]
                .try_into()
                .expect("Unreachable");
            let (mut a1, mut a0) = from_u8_8_to_u32u32(&block);

            for round in (1..32).rev() {
                (a1, a0) = self.G(self.get_round_key(round), a1, a0);
            }
            (a1, a0) = self.GnT(self.key[0], a1, a0);

            for j in 0..4 {
                bytes[i * 8 + j] = ((a1 >> ((3 - j) * 8)) & 0xFF) as u8;
            }
            for j in 0..4 {
                bytes[i * 8 + 4 + j] = (a0 >> ((3 - j) * 8) & 0xFF) as u8;
            }
        }
        self.depadding(&mut bytes);
        bytes
    }

    fn t(&self, v: u32) -> u32 {
        let mut res = 0_u32;
        for i in 0..8 {
            let b = (v >> (4 * i)) & 0xF;
            res |= (PI[i][b as usize] as u32) << (4 * i);
        }
        res
    }

    fn g(&self, k: u32, v: u32) -> u32 {
        self.t(v.wrapping_add(k)).rotate_left(11)
    }

    #[allow(non_snake_case)]
    fn G(&self, k: u32, a1: u32, a0: u32) -> (u32, u32) {
        (a0, self.g(k, a0) ^ a1)
    }

    #[allow(non_snake_case)]
    fn GnT(&self, k: u32, a1: u32, a0: u32) -> (u32, u32) {
        (self.g(k, a0) ^ a1, a0)
    }

    fn padding(&self, bytes: &mut Vec<u8>) {
        let padding = 8 - (bytes.len() % 8);
        bytes.push(1_u8);
        for _ in 1..padding {
            bytes.push(0_u8);
        }
    }

    fn depadding(&self, bytes: &mut Vec<u8>) {
        while *bytes.last().unwrap() != 1_u8 {
            bytes.pop();
        }
        bytes.pop();
    }

    fn get_round_key(&self, round: i32) -> u32 {
        match round {
            0 | 8 | 16 | 31 => self.key[0],
            1 | 9 | 17 | 30 => self.key[1],
            2 | 10 | 18 | 29 => self.key[2],
            3 | 11 | 19 | 28 => self.key[3],
            4 | 12 | 20 | 27 => self.key[4],
            5 | 13 | 21 | 26 => self.key[5],
            6 | 14 | 22 | 25 => self.key[6],
            7 | 15 | 23 | 24 => self.key[7],
            _ => unreachable!(),
        }
    }
}

fn from_u8_32_to_u32_8(bytes: &[u8; 32]) -> [u32; 8] {
    let mut res = [0_u32; 8];
    for i in 0..8 {
        let bytes: [u8; 4] = bytes[(i * 4)..((i + 1) * 4)]
            .try_into()
            .expect("Unreachable");
        res[i] = u32::from_be_bytes(bytes);
    }
    res
}

fn from_u8_8_to_u32u32(bytes: &[u8; 8]) -> (u32, u32) {
    (
        u32::from_be_bytes(bytes[0..4].try_into().expect("Unreachable")),
        u32::from_be_bytes(bytes[4..8].try_into().expect("Unreachable")),
    )
}

pub const PI: [[u8; 16]; 8] = [
    // π₀'
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    // π₁'
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    // π₂'
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    // π₃'
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    // π₄'
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    // π₅'
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    // π₆'
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    // π₇'
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

#[cfg(test)]
mod tests {
    use crate::Magma;

    const TEST_KEY: [u8; 32] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
        0xFE, 0xFF,
    ];
    const MSG: &'static str = "Hello world";

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = Magma::new(&TEST_KEY);
        let ciphertext = cipher.encrypt(MSG);

        // https://gchq.github.io/CyberChef/#recipe=GOST_Encrypt(%7B'option':'Hex','string':'FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'%7D,%7B'option':'Hex','string':''%7D,'Raw','Raw','GOST%20R%2034.12%20(Magma,%202015)','E-TEST','ECB','NO','BIT')To_Hex('0x%20with%20comma',0)&input=SGVsbG8gd29ybGQ
        assert_eq!(
            ciphertext,
            [
                0xF6, 0xB8, 0x32, 0x81, 0x28, 0xA0, 0x09, 0x66, 0xDB, 0x87, 0x86, 0x9E, 0xDB, 0xBD,
                0xF3, 0x61
            ]
        );

        let plaintext = String::from_utf8(cipher.decrypt(ciphertext)).unwrap();
        assert_eq!(plaintext, MSG)
    }
}
