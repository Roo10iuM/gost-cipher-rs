pub fn padding(bytes: &mut Vec<u8>, base: i32) {
    let padding = base - ((bytes.len() as i32) % base);
    bytes.push(1_u8);
    for _ in 1..padding {
        bytes.push(0_u8);
    }
}

pub fn depadding(bytes: &mut Vec<u8>) {
    while *bytes.last().unwrap() != 1_u8 {
        bytes.pop();
    }
    bytes.pop();
}
