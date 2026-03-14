# GOST R 34.12-2015: "Magma" and "Kuznyechik"

## Examples

```rust
use gost_cipher_rs::Magma;

fn main() {
    let key = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    ];
    let cipher = Magma::new(&key);
    let ciphertext = cipher.encrypt(
"Program testing can be a very effective way to show the presence of bugs, \
but it is hopelessly inadequate for showing their absence.",
    );
    let raw_message = cipher.decrypt(ciphertext);
    let message = String::from_utf8(raw_message).unwrap();
    println!("{message}");
}
```
