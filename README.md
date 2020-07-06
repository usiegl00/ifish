# Ifish

-----

This project is not secure.

If you have any questions or ideas please open an issue.

## Building

---

You will need [crystal](https://crystal-lang.org/install), [ruby](https://rvm.io) and [rust](https://rustup.rs).

### cr
```bash
crystal build ifish.cr --release
crystal build ifishe.cr --release
crystal build ifishd.cr --release
```

### rb
```bash
ruby -e 'puts "Built."'
```

### rs
```bash
cargo build --release
```

## Usage

---

The code should not be used in a production environment.

### cr
```bash
# Encrypt Confidential.txt
./ifishe Confidential.txt > Confidential.ifsh
# Decrypt Confidential.ifsh
./ifishd Confidential.ifsh
# Hash Confidential.txt
./ifish Confidential.txt
```

### rb
```bash
# Encrypt Confidential.txt
ruby Sagi.rb Confidential.txt > Confidential.kda
# Decrypt Confidential.sga
ruby Kada.rb Confidential.kda
# Hash Confidential.txt
ruby Irla.rb Confidential.txt
```

### rs
```bash
# Hash Confidential.txt
./target/release/ifish Confidential.txt
```

## Code structure
The code is seperated into three directories:
- `cr` (Crystal)
- `rb` (Ruby)
- `rs` (Rust)

In the `cr` directory there is an SIV (ifishe,ifishd) and a PRF (ifish).

In the `rb` directory there is an SIV (Sagi,Kada) and a PRF (Irla).

In the `rs` directory there is an PRF (ifish).

## Links
- [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))
- [SIV](https://tools.ietf.org/id/draft-madden-generalised-siv-00.html)
- [CMAC](https://en.wikipedia.org/wiki/One-key_MAC)
- [OWCF](https://en.wikipedia.org/wiki/One-way_compression_function)
