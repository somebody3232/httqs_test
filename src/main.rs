use std::io::{Read, Write};
use std::net::TcpStream;
use aes::cipher::KeyInit;
use pqc_kyber::*;
use rand::Rng;
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
    let mut alice = Uake::new();
    // Receive Bob's public key from the server
    let mut bob_keys = [0u8; 1184];
    stream.read(&mut bob_keys).unwrap();
    // Alice initiates key exchange
    let client_init = alice.client_init(&bob_keys, &mut rng);
    // Send the client_init to the server
    stream.write(&client_init).unwrap();
    // Receive the server_response from the server
    let mut server_response = [0u8; 1088];
    stream.read(&mut server_response).unwrap();
    alice.client_confirm(server_response).unwrap();
    println!("Client: {:?}", alice.shared_secret);

    if let Some(fileReq) = std::env::args().nth(2){
        // Use the shared secret to encrypt and decrypt messages, starting with the file request
        // Encrypt the file name we're requesting

    }


}
fn server() {
    println!("Running server");
    let mut rng = rand::thread_rng();
    let mut bob = Uake::new();
    // Generate Bob's Keypair
    let bob_keys = keypair(&mut rng);
    // Check if the ip is in use and ok to start
    // Host the server for the client to connect to
    let listener = std::net::TcpListener::bind("127.0.0.1:1332").unwrap();
    loop {
        let (mut stream, _) = listener.accept().unwrap();
        // Send Bob's public key to the client
        stream.write(&bob_keys.public).unwrap();
        // Receive the client_init from the client
        let mut client_init = [0u8; 2272];
        stream.read(&mut client_init).unwrap();
        let server_response = bob.server_receive(
            client_init, &bob_keys.secret, &mut rng
        ).unwrap();
        // Send the server_response to the client
        stream.write(&server_response).unwrap();
        println!("Server: {:?}", bob.shared_secret);

        // // Use the shared secret to encrypt and decrypt messages, starting with the file request using aes
        // // Receive the encrypted file request from the client
        // let mut file_request_encrypted = [0u8; 16];
        // stream.read(&mut file_request_encrypted).unwrap();
        // // Decrypt the file request
        // let mut file_request_decrypted = [0u8; 16];
        // let mut cipher = aes::Aes128Ctr::new(&bob.shared_secret, &bob.shared_secret);
        // cipher.apply_keystream(&mut file_request_decrypted);
        // // Print the decrypted file request
        // println!("File Request: {:?}", file_request_decrypted);
        // // Encrypt the file
        // let file = "message.txt";
        // let mut file_encrypted = [0u8; 16];
        // let mut cipher = aes::Aes128Ctr::new(&bob.shared_secret, &bob.shared_secret);
        // cipher.apply_keystream(&mut file_encrypted);
        // // Send the encrypted file to the client
        // stream.write(&file_encrypted).unwrap();
    }
        // Loop the server
    // stream.shutdown(std::net::Shutdown::Both).unwrap();
    // disable the listener and stream to prevent AddrInUse error
    // drop(listener);
    // server();
}