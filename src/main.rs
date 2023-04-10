use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aead::rand_core::SeedableRng;
use pqc_kyber::*;

fn main() {
    println!("Hello, world!");
    // if run with --client, run the client else run the server
    if std::env::args().nth(1) == Some("--client".to_string()) {
        client();
    } else {
        server();
    }
    // Thread the server and run the client
    // std::thread::spawn(|| server());
    // client();
}

fn client() {
    println!("Running client");
    let mut rng = rand::thread_rng();
    let mut stream = TcpStream::connect("127.0.0.1:1332").unwrap();
    let mut client = Uake::new();
    // Receive Server's public key
    let mut server_key = [0u8; 1184];
    stream.read_exact(&mut server_key).unwrap();
    // Client initiates key exchange
    let client_init = client.client_init(&server_key, &mut rng);
    // Send the client_init to the server
    stream.write_all(&client_init).unwrap();
    // Receive the server_response from the server
    let mut server_response = [0u8; 1088];
    stream.read_exact(&mut server_response).unwrap();
    client.client_confirm(server_response).unwrap();
    println!("Client: {:?}", client.shared_secret);

    // if let Some(file_req) = std::env::args().nth(2){
    let file_req = "message.txt";
    // Use the shared secret to encrypt and decrypt messages, starting with the file request
    // Encrypt the file name we're requesting
    // Make a CryptoRng object from the shared secret
    let rng = rand::rngs::StdRng::from_seed(client.shared_secret);
    let key = Aes256GcmSiv::generate_key(rng);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce");
    let ciphertext = cipher.encrypt(nonce, file_req.as_bytes()).unwrap();

    // Send the encrypted file request to the server
    println!("File Request: {:?} Written", file_req);
    stream.write_all(&ciphertext).unwrap();


    // println!("Encrypted File Request: {:?}", ciphertext);

    // Receive the encrypted file contents from the server
    println!("Going to read to end");
    let mut file_contents_encrypted: Vec<u8> = Vec::new();
    stream.read_to_end(&mut file_contents_encrypted).unwrap();

    // Decrypt the file contents
    let file_contents_decrypted = cipher.decrypt(nonce, file_contents_encrypted.as_slice()).unwrap();

    // Print the decrypted file contents
    println!("Decrypted File Contents: {:?}", String::from_utf8(file_contents_decrypted).unwrap());

    // // print the encrypted file contents
    // println!("Encrypted File Contents: {:?}", file_contents_encrypted);
}

fn server() {
    println!("Running server");
    let mut rng = rand::thread_rng();
    let mut server = Uake::new();
    // Generate Server's Keypair
    let server_keys = keypair(&mut rng);
    // Check if the ip is in use and ok to start
    // Host the server for the client to connect to
    let listener = std::net::TcpListener::bind("127.0.0.1:1332").unwrap();
    loop {
        let (mut stream, _) = listener.accept().unwrap();
        println!("\nConnection established!");
        // Send Server's public key to the client
        stream.write_all(&server_keys.public).unwrap();
        // Receive the client_init from the client
        let mut client_init = [0u8; 2272];
        stream.read_exact(&mut client_init).unwrap();
        let server_response = server.server_receive(
            client_init, &server_keys.secret, &mut rng,
        ).unwrap();
        // Send the server_response to the client
        stream.write_all(&server_response).unwrap();
        println!("\x1b[96mEstablished Shared Secret\x1b[0m");

        // Receive the encrypted file request from the client
        let mut file_request_encrypted: Vec<u8> = Vec::new();
        stream.read_to_end(&mut file_request_encrypted).unwrap();
        println!("File Request Received");

        // If we got a file request, decrypt it
        // Get ready to decrypt the file request
        let rng = rand::rngs::StdRng::from_seed(server.shared_secret);
        let key = Aes256GcmSiv::generate_key(rng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce");

        // Decrypt the file request
        let file_request_decrypted = cipher.decrypt(nonce, file_request_encrypted.as_slice()).unwrap();

        // Print the decrypted file request
        println!("\x1b[34mGot File Request {:?}\x1b[0m", String::from_utf8(file_request_decrypted.clone()).unwrap());

        // Open the file requested
        let mut file = std::fs::File::open(String::from_utf8(file_request_decrypted).unwrap()).unwrap();
        let mut file_contents: Vec<u8> = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();

        // Encrypt the file contents
        let file_contents_encrypted = cipher.encrypt(nonce, file_contents.as_slice()).unwrap();

        // Send the encrypted file contents to the client
        stream.write_all(&file_contents_encrypted).unwrap();

        // Print the encrypted file contents
        // println!("Encrypted File Contents: {:?}", file_contents_encrypted);
    }
}