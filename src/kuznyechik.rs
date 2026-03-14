use crate::common::{depadding, padding};

pub struct Kuznyechik {
    keys: [[u8; 16]; 10],
}

impl Kuznyechik {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut keys = [[0u8; 16]; 10];

        keys[0].copy_from_slice(&key[0..16]);
        keys[1].copy_from_slice(&key[16..32]);
        let mut a = keys[0];
        let mut b = keys[1];
        for i in 0..4 {
            for j in 0..8 {
                F(&C[(i * 8 + j) as usize], &mut a, &mut b);
            }
            keys[2 * i + 2] = a;
            keys[2 * i + 3] = b;
        }

        Self { keys: keys }
    }

    pub fn encrypt<B: Into<Vec<u8>>>(&self, plaintext: B) -> Vec<u8> {
        let mut bytes = plaintext.into();
        padding(&mut bytes, 16);
        for i in 0..(bytes.len() / 16) {
            let mut block: [u8; 16] =
                bytes[(i * 16)..((i + 1) * 16)].try_into().unwrap();
            for round in 0..9 {
                X(&self.keys[round], &mut block);
                S(&mut block);
                L(&mut block);
            }
            X(&self.keys[9], &mut block);
            bytes[(i * 16)..((i + 1) * 16)].copy_from_slice(&block);
        }
        bytes
    }

    pub fn decrypt<B: Into<Vec<u8>>>(&self, ciphertext: B) -> Vec<u8> {
        let mut bytes = ciphertext.into();
        for i in 0..(bytes.len() / 16) {
            let mut block: [u8; 16] =
                bytes[(i * 16)..((i + 1) * 16)].try_into().unwrap();
            for round in (1..10).rev() {
                X(&self.keys[round], &mut block);
                L_INV(&mut block);
                S_INV(&mut block);
            }
            X(&self.keys[0], &mut block);
            bytes[(i * 16)..((i + 1) * 16)].copy_from_slice(&block);
        }
        depadding(&mut bytes);
        bytes
    }
}

fn l(bytes: &[u8; 16]) -> u8 {
    gf_mul(bytes[0], 148)
        ^ gf_mul(bytes[1], 32)
        ^ gf_mul(bytes[2], 133)
        ^ gf_mul(bytes[3], 16)
        ^ gf_mul(bytes[4], 194)
        ^ gf_mul(bytes[5], 192)
        ^ bytes[6]
        ^ gf_mul(bytes[7], 251)
        ^ bytes[8]
        ^ gf_mul(bytes[9], 192)
        ^ gf_mul(bytes[10], 194)
        ^ gf_mul(bytes[11], 16)
        ^ gf_mul(bytes[12], 133)
        ^ gf_mul(bytes[13], 32)
        ^ gf_mul(bytes[14], 148)
        ^ bytes[15]
}

#[allow(non_snake_case)]
fn X(key: &[u8; 16], bytes: &mut [u8; 16]) {
    for i in 0..16 {
        bytes[i] ^= key[i];
    }
}

#[allow(non_snake_case)]
fn S(bytes: &mut [u8; 16]) {
    bytes[0] = PI[bytes[0] as usize];
    bytes[1] = PI[bytes[1] as usize];
    bytes[2] = PI[bytes[2] as usize];
    bytes[3] = PI[bytes[3] as usize];
    bytes[4] = PI[bytes[4] as usize];
    bytes[5] = PI[bytes[5] as usize];
    bytes[6] = PI[bytes[6] as usize];
    bytes[7] = PI[bytes[7] as usize];
    bytes[8] = PI[bytes[8] as usize];
    bytes[9] = PI[bytes[9] as usize];
    bytes[10] = PI[bytes[10] as usize];
    bytes[11] = PI[bytes[11] as usize];
    bytes[12] = PI[bytes[12] as usize];
    bytes[13] = PI[bytes[13] as usize];
    bytes[14] = PI[bytes[14] as usize];
    bytes[15] = PI[bytes[15] as usize];
}

#[allow(non_snake_case)]
fn S_INV(bytes: &mut [u8; 16]) {
    bytes[0] = PI_INV[bytes[0] as usize];
    bytes[1] = PI_INV[bytes[1] as usize];
    bytes[2] = PI_INV[bytes[2] as usize];
    bytes[3] = PI_INV[bytes[3] as usize];
    bytes[4] = PI_INV[bytes[4] as usize];
    bytes[5] = PI_INV[bytes[5] as usize];
    bytes[6] = PI_INV[bytes[6] as usize];
    bytes[7] = PI_INV[bytes[7] as usize];
    bytes[8] = PI_INV[bytes[8] as usize];
    bytes[9] = PI_INV[bytes[9] as usize];
    bytes[10] = PI_INV[bytes[10] as usize];
    bytes[11] = PI_INV[bytes[11] as usize];
    bytes[12] = PI_INV[bytes[12] as usize];
    bytes[13] = PI_INV[bytes[13] as usize];
    bytes[14] = PI_INV[bytes[14] as usize];
    bytes[15] = PI_INV[bytes[15] as usize];
}

#[allow(non_snake_case)]
fn R(bytes: &mut [u8; 16]) {
    let tmp = l(bytes);
    for i in (1..16).rev() {
        bytes[i] = bytes[i - 1];
    }
    bytes[0] = tmp;
}

#[allow(non_snake_case)]
fn L(bytes: &mut [u8; 16]) {
    for _ in 0..16 {
        R(bytes);
    }
}

#[allow(non_snake_case)]
fn R_INV(bytes: &mut [u8; 16]) {
    let tmp = bytes[0];
    for i in 0..15 {
        bytes[i] = bytes[i + 1];
    }
    bytes[15] = tmp;
    bytes[15] = l(bytes);
}

#[allow(non_snake_case)]
fn L_INV(bytes: &mut [u8; 16]) {
    for _ in 0..16 {
        R_INV(bytes);
    }
}

#[allow(non_snake_case)]
fn F(key: &[u8; 16], a1: &mut [u8; 16], a0: &mut [u8; 16]) {
    let mut tmp = a1.clone();
    X(key, &mut tmp);
    S(&mut tmp);
    L(&mut tmp);
    for i in 0..16 {
        tmp[i] ^= a0[i];
    }
    a0.copy_from_slice(a1);
    a1.copy_from_slice(&tmp);
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            res ^= a;
        }
        let hi_bit_set = a & 0x80 != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0xC3;
        }
        b >>= 1;
    }
    res
}

const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4,
    77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20,
    205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237,
    152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
    104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191,
    114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199,
    243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53,
    138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
    62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
    222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
    96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69,
    70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7,
    88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231,
    137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202,
    216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208,
    190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102,
    175, 194, 57, 75, 99, 182,
];

const PI_INV: [u8; 256] = [
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82,
    145, 100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164,
    63, 224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228,
    21, 183, 200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42,
    115, 132, 213, 195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159,
    253, 212, 15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127, 193,
    240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172, 34, 249,
    226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113,
    86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210,
    49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105,
    179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 55,
    97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51,
    250, 150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151,
    125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232,
    79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11,
    19, 152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16,
    68, 64, 146, 58, 1, 38, 18, 26, 72, 104, 245, 129, 139, 199, 214,
    32, 10, 8, 0, 76, 215, 116,
];

const C: [[u8; 16]; 32] = [
    [
        0x6e, 0xa2, 0x76, 0x72, 0x6c, 0x48, 0x7a, 0xb8, 0x5d, 0x27,
        0xbd, 0x10, 0xdd, 0x84, 0x94, 0x01,
    ],
    [
        0xdc, 0x87, 0xec, 0xe4, 0xd8, 0x90, 0xf4, 0xb3, 0xba, 0x4e,
        0xb9, 0x20, 0x79, 0xcb, 0xeb, 0x02,
    ],
    [
        0xb2, 0x25, 0x9a, 0x96, 0xb4, 0xd8, 0x8e, 0x0b, 0xe7, 0x69,
        0x04, 0x30, 0xa4, 0x4f, 0x7f, 0x03,
    ],
    [
        0x7b, 0xcd, 0x1b, 0x0b, 0x73, 0xe3, 0x2b, 0xa5, 0xb7, 0x9c,
        0xb1, 0x40, 0xf2, 0x55, 0x15, 0x04,
    ],
    [
        0x15, 0x6f, 0x6d, 0x79, 0x1f, 0xab, 0x51, 0x1d, 0xea, 0xbb,
        0x0c, 0x50, 0x2f, 0xd1, 0x81, 0x05,
    ],
    [
        0xa7, 0x4a, 0xf7, 0xef, 0xab, 0x73, 0xdf, 0x16, 0x0d, 0xd2,
        0x08, 0x60, 0x8b, 0x9e, 0xfe, 0x06,
    ],
    [
        0xc9, 0xe8, 0x81, 0x9d, 0xc7, 0x3b, 0xa5, 0xae, 0x50, 0xf5,
        0xb5, 0x70, 0x56, 0x1a, 0x6a, 0x07,
    ],
    [
        0xf6, 0x59, 0x36, 0x16, 0xe6, 0x05, 0x56, 0x89, 0xad, 0xfb,
        0xa1, 0x80, 0x27, 0xaa, 0x2a, 0x08,
    ],
    [
        0x98, 0xfb, 0x40, 0x64, 0x8a, 0x4d, 0x2c, 0x31, 0xf0, 0xdc,
        0x1c, 0x90, 0xfa, 0x2e, 0xbe, 0x09,
    ],
    [
        0x2a, 0xde, 0xda, 0xf2, 0x3e, 0x95, 0xa2, 0x3a, 0x17, 0xb5,
        0x18, 0xa0, 0x5e, 0x61, 0xc1, 0x0a,
    ],
    [
        0x44, 0x7c, 0xac, 0x80, 0x52, 0xdd, 0xd8, 0x82, 0x4a, 0x92,
        0xa5, 0xb0, 0x83, 0xe5, 0x55, 0x0b,
    ],
    [
        0x8d, 0x94, 0x2d, 0x1d, 0x95, 0xe6, 0x7d, 0x2c, 0x1a, 0x67,
        0x10, 0xc0, 0xd5, 0xff, 0x3f, 0x0c,
    ],
    [
        0xe3, 0x36, 0x5b, 0x6f, 0xf9, 0xae, 0x07, 0x94, 0x47, 0x40,
        0xad, 0xd0, 0x08, 0x7b, 0xab, 0x0d,
    ],
    [
        0x51, 0x13, 0xc1, 0xf9, 0x4d, 0x76, 0x89, 0x9f, 0xa0, 0x29,
        0xa9, 0xe0, 0xac, 0x34, 0xd4, 0x0e,
    ],
    [
        0x3f, 0xb1, 0xb7, 0x8b, 0x21, 0x3e, 0xf3, 0x27, 0xfd, 0x0e,
        0x14, 0xf0, 0x71, 0xb0, 0x40, 0x0f,
    ],
    [
        0x2f, 0xb2, 0x6c, 0x2c, 0x0f, 0x0a, 0xac, 0xd1, 0x99, 0x35,
        0x81, 0xc3, 0x4e, 0x97, 0x54, 0x10,
    ],
    [
        0x41, 0x10, 0x1a, 0x5e, 0x63, 0x42, 0xd6, 0x69, 0xc4, 0x12,
        0x3c, 0xd3, 0x93, 0x13, 0xc0, 0x11,
    ],
    [
        0xf3, 0x35, 0x80, 0xc8, 0xd7, 0x9a, 0x58, 0x62, 0x23, 0x7b,
        0x38, 0xe3, 0x37, 0x5c, 0xbf, 0x12,
    ],
    [
        0x9d, 0x97, 0xf6, 0xba, 0xbb, 0xd2, 0x22, 0xda, 0x7e, 0x5c,
        0x85, 0xf3, 0xea, 0xd8, 0x2b, 0x13,
    ],
    [
        0x54, 0x7f, 0x77, 0x27, 0x7c, 0xe9, 0x87, 0x74, 0x2e, 0xa9,
        0x30, 0x83, 0xbc, 0xc2, 0x41, 0x14,
    ],
    [
        0x3a, 0xdd, 0x01, 0x55, 0x10, 0xa1, 0xfd, 0xcc, 0x73, 0x8e,
        0x8d, 0x93, 0x61, 0x46, 0xd5, 0x15,
    ],
    [
        0x88, 0xf8, 0x9b, 0xc3, 0xa4, 0x79, 0x73, 0xc7, 0x94, 0xe7,
        0x89, 0xa3, 0xc5, 0x09, 0xaa, 0x16,
    ],
    [
        0xe6, 0x5a, 0xed, 0xb1, 0xc8, 0x31, 0x09, 0x7f, 0xc9, 0xc0,
        0x34, 0xb3, 0x18, 0x8d, 0x3e, 0x17,
    ],
    [
        0xd9, 0xeb, 0x5a, 0x3a, 0xe9, 0x0f, 0xfa, 0x58, 0x34, 0xce,
        0x20, 0x43, 0x69, 0x3d, 0x7e, 0x18,
    ],
    [
        0xb7, 0x49, 0x2c, 0x48, 0x85, 0x47, 0x80, 0xe0, 0x69, 0xe9,
        0x9d, 0x53, 0xb4, 0xb9, 0xea, 0x19,
    ],
    [
        0x05, 0x6c, 0xb6, 0xde, 0x31, 0x9f, 0x0e, 0xeb, 0x8e, 0x80,
        0x99, 0x63, 0x10, 0xf6, 0x95, 0x1a,
    ],
    [
        0x6b, 0xce, 0xc0, 0xac, 0x5d, 0xd7, 0x74, 0x53, 0xd3, 0xa7,
        0x24, 0x73, 0xcd, 0x72, 0x01, 0x1b,
    ],
    [
        0xa2, 0x26, 0x41, 0x31, 0x9a, 0xec, 0xd1, 0xfd, 0x83, 0x52,
        0x91, 0x03, 0x9b, 0x68, 0x6b, 0x1c,
    ],
    [
        0xcc, 0x84, 0x37, 0x43, 0xf6, 0xa4, 0xab, 0x45, 0xde, 0x75,
        0x2c, 0x13, 0x46, 0xec, 0xff, 0x1d,
    ],
    [
        0x7e, 0xa1, 0xad, 0xd5, 0x42, 0x7c, 0x25, 0x4e, 0x39, 0x1c,
        0x28, 0x23, 0xe2, 0xa3, 0x80, 0x1e,
    ],
    [
        0x10, 0x03, 0xdb, 0xa7, 0x2e, 0x34, 0x5f, 0xf6, 0x64, 0x3b,
        0x95, 0x33, 0x3f, 0x27, 0x14, 0x1f,
    ],
    [
        0x5e, 0xa7, 0xd8, 0x58, 0x1e, 0x14, 0x9b, 0x61, 0xf1, 0x6a,
        0xc1, 0x45, 0x9c, 0xed, 0xa8, 0x20,
    ],
];

#[cfg(test)]
mod tests {
    use crate::Kuznyechik;

    const TEST_KEY: [u8; 32] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66,
        0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xF0, 0xF1, 0xF2, 0xF3,
        0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
        0xFE, 0xFF,
    ];
    const MSG: &'static str = "Hello world";

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = Kuznyechik::new(&TEST_KEY);
        let ciphertext = cipher.encrypt(MSG);

        // https://gchq.github.io/CyberChef/#recipe=GOST_Encrypt(%7B'option':'Hex','string':'FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF'%7D,%7B'option':'Hex','string':''%7D,'Raw','Raw','GOST%20R%2034.12%20(Kuznyechik,%202015)','E-TEST','ECB','NO','BIT')To_Hex('0x%20with%20comma',0)&input=SGVsbG8gd29ybGQ
        assert_eq!(
            ciphertext,
            [
                0xD4, 0xE7, 0x46, 0xC7, 0x7D, 0x26, 0x34, 0x48, 0x86,
                0xE6, 0x01, 0x72, 0xBA, 0x62, 0xA9, 0x9B
            ]
        );

        let plaintext =
            String::from_utf8(cipher.decrypt(ciphertext)).unwrap();
        assert_eq!(plaintext, MSG)
    }
}
