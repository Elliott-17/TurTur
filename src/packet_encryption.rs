use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};


pub fn encrypt_packet(packet: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(&key);
    let block_size = 16;
    let mut padded_packet = packet.to_vec();
    
    // Padding the packet to ensure it's a multiple of the block size
    let pad_len = block_size - (padded_packet.len() % block_size);
    padded_packet.extend(vec![pad_len as u8; pad_len].iter());

    let mut encrypted_packet = Vec::with_capacity(padded_packet.len());
    for chunk in padded_packet.chunks_mut(block_size) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_packet.extend_from_slice(&block);
    }

    encrypted_packet
}

pub fn decrypt_packet(packet: &[u8], key: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256::new(&key);

    let mut decrypted_packet = packet.to_vec();
    for chunk in decrypted_packet.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }

    decrypted_packet
}


