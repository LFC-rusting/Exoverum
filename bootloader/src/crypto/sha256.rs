//! Implementação própria de SHA-256 (FIPS 180-4), sem dependências, sem alocação.
//!
//! Motivação: a regra do projeto proíbe crates externas e exige TCB mínima; como
//! preciso verificar o hash do ELF do kernel antes do ExitBootServices, incluí
//! aqui uma versão pequena, safe e auditável. Testes contra vetores conhecidos ficam
//! no próprio módulo para permitir `cargo test` no host.

#![forbid(unsafe_code)]

use core::convert::TryInto;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Calcula SHA-256 de `data` em um único passo, sem alocação dinâmica.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // Processo blocos cheios e depois SEMPRE rodo o padding final — mesmo
    // quando `data` é vazio ou múltiplo exato de 64, o último bloco padded
    // deve ser comprimido (requisito FIPS 180-4).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut buffer = [0u8; 64];
    let mut h = H0;

    let full = data.len() / 64;
    for i in 0..full {
        buffer.copy_from_slice(&data[i * 64..(i + 1) * 64]);
        compress(&mut h, &buffer);
    }
    let rest = &data[full * 64..];

    let mut last = [0u8; 128];
    let mut idx = 0;
    for &b in rest {
        last[idx] = b;
        idx += 1;
    }
    last[idx] = 0x80;
    idx += 1;

    // Se sobra menos de 8 bytes até o fim do bloco, o comprimento cai no
    // próximo bloco (padding de 2 blocos).
    let two_blocks = idx > 56;
    let len_pos = if two_blocks { 120 } else { 56 };
    last[len_pos..len_pos + 8].copy_from_slice(&bit_len.to_be_bytes());

    let total = if two_blocks { 128 } else { 64 };
    let mut processed = 0;
    while processed < total {
        buffer.copy_from_slice(&last[processed..processed + 64]);
        compress(&mut h, &buffer);
        processed += 64;
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for t in 0..16 {
        let start = t * 4;
        w[t] = u32::from_be_bytes(block[start..start + 4].try_into().unwrap());
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::sha256;

    fn hex(bytes: &[u8; 32]) -> [u8; 64] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 64];
        for (i, b) in bytes.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        out
    }

    #[test]
    fn vetor_empty() {
        let h = sha256(b"");
        let esperado = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(&hex(&h), esperado);
    }

    #[test]
    fn vetor_abc() {
        let h = sha256(b"abc");
        let esperado = b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(&hex(&h), esperado);
    }

    #[test]
    fn vetor_exato_64_bytes() {
        // Caso-limite: input exato de 1 bloco exige um bloco extra só de padding.
        let data = [b'a'; 64];
        let h = sha256(&data);
        let esperado = b"ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
        assert_eq!(&hex(&h), esperado);
    }

    #[test]
    fn vetor_56_bytes() {
        // Exatamente 56 bytes força o caso de padding que precisa de 2 blocos.
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let h = sha256(data);
        let esperado = b"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        assert_eq!(&hex(&h), esperado);
    }

    // Vetores NIST FIPS 180-4 adicionais para endurecer a confiança.
    // Cobrem: entrada de 1 byte, entrada de 2 blocos exatos (112 B) e o
    // caso longo canônico de 1 milhão de 'a' (multiplos blocos cheios + padding).

    #[test]
    fn vetor_um_byte() {
        let h = sha256(b"a");
        let esperado = b"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        assert_eq!(&hex(&h), esperado);
    }

    #[test]
    fn vetor_112_bytes_dois_blocos() {
        let data = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(data.len(), 112);
        let h = sha256(data);
        let esperado = b"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
        assert_eq!(&hex(&h), esperado);
    }

    #[test]
    fn vetor_um_milhao_de_a() {
        // Caso canônico NIST: 1_000_000 bytes 'a'. Exercita muitas iterações
        // do laço de blocos cheios e detecta qualquer drift no offset/length.
        let data = [b'a'; 1_000_000];
        let h = sha256(&data);
        let esperado = b"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        assert_eq!(&hex(&h), esperado);
    }
}
