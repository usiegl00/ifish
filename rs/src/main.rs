fn to_arr(t: (u32, u32)) -> [u32; 2] {[t.0.into(), t.1.into()]}
fn vec_to_arr(v: Vec<u32>) -> [u32; 2] {[v[0],v[1]]}
fn v8_to_arr(v: Vec<u8>) -> [u8; 8] {[v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7]]}
fn slice_to_arr(s: &[u8]) -> [u8; 8] {[s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]]}
fn main() {
    let mut m = Vec::new();
    std::io::Read::read_to_end(&mut std::fs::File::open(&std::env::args().collect::<Vec<String>>()[1]).unwrap(), &mut m).unwrap();
    let m = m[..].chunks_exact(8);
    let mut d = m.remainder().to_vec();
    d.push(128);
    for _ in std::iter::repeat(()).take(8 - d.len()) {d.push(0)}
    let mut b = crypto::blowfish::Blowfish::init_state();
    let mut h: [u32; 2] = [0, 0];
    let mut g: [u32; 2] = [0, 0];
    let mut r: [u32; 2] = [0, 0];
    for c in m {
        b.expand_key(&[unsafe{std::mem::transmute::<[u32;2],[u8;8]>(h)},slice_to_arr(c)].concat());
        r[0] = g[0] ^ 255;
        r[1] = g[1] ^ 255;
        g = vec_to_arr(to_arr(b.encrypt(g[0], g[1])).iter().zip(g.iter()).map(|(a,b)| a ^ b).collect::<Vec<u32>>());
        h = vec_to_arr(to_arr(b.encrypt(r[0], r[1])).iter().zip(r.iter()).map(|(a,b)| a ^ b).collect::<Vec<u32>>());
    }
    b.expand_key(&[unsafe{std::mem::transmute::<[u32;2],[u8;8]>(h)},v8_to_arr(d)].concat());
    r[0] = g[0] ^ 255;
    r[1] = g[1] ^ 255;
    g = vec_to_arr(to_arr(b.encrypt(g[0], g[1])).iter().zip(g.iter()).map(|(a,b)| a ^ b).collect::<Vec<u32>>());
    h = vec_to_arr(to_arr(b.encrypt(r[0], r[1])).iter().zip(r.iter()).map(|(a,b)| a ^ b).collect::<Vec<u32>>());
    println!("{:x}{:x}{:x}{:x}", h[0], h[1], g[0], g[1]);
}
