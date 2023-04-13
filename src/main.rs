use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm_siv::aead::rand_core::SeedableRng;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use pqc_kyber::*;

fn main() {
    // Check if run with --silent anywhere, and pass that to the server and client
    let mut is_silent = false;
    let mut is_client = false;
    let mut save_to_file = false;
    let mut url = String::from("127.0.0.1:1332");
    let mut file_req = String::from("message.txt");
    for arg in std::env::args() {
        if arg == "--silent" {
            is_silent = true;
        }
        if arg == "--client" {
            is_client = true;
        }
        if arg.contains("--url=") {
            url = arg.replace("--url=", "");
        }
        if arg.contains("--file=") {
            file_req = arg.replace("--file=", "");
        }
        if arg == "--save" {
            save_to_file = true;
        }
    }
    // if run with --client, run the client else run the server
    if is_client {
        client(is_silent, url, file_req, save_to_file);
    } else {
        server(is_silent, url);
    }
    // Thread the server and run the client
    // std::thread::spawn(|| server());
    // client();
}

fn client(is_silent: bool, url: String, file_req: String, save_to_file: bool) {
    if !is_silent {
        println!("\nRunning client");
    }
    let mut rng = rand::thread_rng();
    let mut stream = TcpStream::connect(url).unwrap();
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
    if !is_silent {
        println!("Established Shared Secret");
    }

    // Use the shared secret to encrypt and decrypt messages, starting with the file request
    // Encrypt the file name we're requesting
    // Make a Rng object from the shared secret
    let rng = rand::rngs::StdRng::from_seed(client.shared_secret);
    let key = Aes256GcmSiv::generate_key(rng);
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(b"unique nonce");
    let ciphertext = cipher.encrypt(nonce, file_req.as_str().as_bytes()).unwrap();

    // Send the encrypted file request to the server, prefixed with the length, with the length number padded to 8 bytes
    let file_req_len = ciphertext.len();
    let file_req_buf = file_req_len.to_be_bytes();

    if !is_silent {
        println!("File Request Length: {:?}", file_req_len);
    }
    let mut file_req_buf_padded = [0u8; 8];
    file_req_buf_padded[8 - file_req_buf.len()..].copy_from_slice(&file_req_buf);
    stream.write_all(&file_req_buf_padded).unwrap();

    if !is_silent {
        println!("File Request: {:?}", file_req);
    }
    stream.write_all(&ciphertext).unwrap();

    // Receive the encrypted file contents from the server
    // Receive the length of the file contents
    let mut file_contents_len_buf = [0u8; 8];
    stream.read_exact(&mut file_contents_len_buf).unwrap();
    let file_contents_len = u64::from_be_bytes(file_contents_len_buf);
    let mut file_contents_encrypted: Vec<u8> = vec![0; file_contents_len as usize];
    stream.read_exact(&mut file_contents_encrypted).unwrap();

    // Decrypt the file contents
    let file_contents_decrypted = cipher
        .decrypt(nonce, file_contents_encrypted.as_slice())
        .unwrap();

    // Print the decrypted file contents
    if !is_silent {
        println!("Decrypted File Contents: ");
    }
    if !save_to_file || !is_silent {
        println!(
            "{}\n",
            String::from_utf8(file_contents_decrypted.clone()).unwrap()
        );
    }

    // Save the file contents to a file
    if save_to_file {
        let path = String::from("httqs_out/") + &*file_req;
        // Create directories if needed
        if !std::path::Path::new("httqs_out").exists() {
            std::fs::create_dir("httqs_out").unwrap();
        }
        // Scaffold the file path if needed (e.g. if the file is in a subdirectory) (ik this is bad, fix later)
        let path = std::path::Path::new(&path);
        if path.parent().is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&file_contents_decrypted).unwrap();
    }
}

fn server(is_silent: bool, url: String) {
    if !is_silent {
        println!("Running server on {:?}", url);
    }
    let mut rng = rand::thread_rng();
    let mut server = Uake::new();
    // Generate Server's Keypair
    let server_keys = keypair(&mut rng);
    // Check if the ip is in use and ok to start
    // Host the server for the client to connect to
    // let listener = std::net::TcpListener::bind("127.0.0.1:1332").unwrap();
    let listener = std::net::TcpListener::bind(url).unwrap();
    loop {
        let (mut stream, _) = listener.accept().unwrap();
        if !is_silent {
            println!("\n\x1b[92mConnection established!\x1b[0m");
        }
        // Send Server's public key to the client
        stream.write_all(&server_keys.public).unwrap();
        // Receive the client_init from the client
        let mut client_init = [0u8; 2272];
        stream.read_exact(&mut client_init).unwrap();
        let server_response = server
            .server_receive(client_init, &server_keys.secret, &mut rng)
            .unwrap();
        // Send the server_response to the client
        stream.write_all(&server_response).unwrap();
        if !is_silent {
            println!("\x1b[96mEstablished Shared Secret\x1b[0m");
        }

        // Receive the encrypted file request from the client
        // Receive the length of the file request
        let mut file_req_len_buf = [0u8; 8];
        stream.read_exact(&mut file_req_len_buf).unwrap();
        let file_req_len = u64::from_be_bytes(file_req_len_buf);
        // println!("File Request Length: {:?}", file_req_len);

        let mut file_request_encrypted: Vec<u8> = vec![0; file_req_len as usize];
        file_request_encrypted.resize(file_req_len as usize, 0);
        stream.read_exact(&mut file_request_encrypted).unwrap();
        // println!("File Request Received: {:?}", file_request_encrypted);

        // If we got a file request, decrypt it
        // Get ready to decrypt the file request
        let rng = rand::rngs::StdRng::from_seed(server.shared_secret);
        let key = Aes256GcmSiv::generate_key(rng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce");

        // Decrypt the file request
        let file_request_decrypted = cipher
            .decrypt(nonce, file_request_encrypted.as_slice())
            .unwrap();

        // Print the decrypted file request
        if !is_silent {
            println!(
                "\x1b[34mGot File Request {:?}\x1b[0m",
                String::from_utf8(file_request_decrypted.clone()).unwrap()
            );
        }

        // Open the file requested
        let mut path =
            String::from("public/") + &*String::from_utf8(file_request_decrypted).unwrap();
        let mut file = std::fs::File::open(path.clone());
        if file.is_err() {
            if !is_silent {
                println!("\x1b[31mFile {:?} not found!\x1b[0m", path);
            }
            file = std::fs::File::open("public/404.html");
            path = String::from("public/404.html");
        }
        let mut file = file.unwrap();
        let mut file_contents: Vec<u8> = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();
        // To read the raw file source, uncomment the following line
        let file_contents = std::fs::read(path).unwrap();

        // Print the file contents
        // if !is_silent { println!("\x1b[34mFile Contents: {}\x1b[0m", String::from_utf8(file_contents.clone()).unwrap()); }

        // Encrypt the file contents
        let file_contents_encrypted = cipher.encrypt(nonce, file_contents.as_slice()).unwrap();

        // Send the encrypted file contents to the client, prefixed with the length, with the length number padded to 8 bytes
        if !is_silent {
            println!("\x1b[95mSending file contents!\x1b[0m");
        }
        let file_contents_len = file_contents_encrypted.len();
        let file_contents_buf = file_contents_len.to_be_bytes();
        let mut file_contents_buf_padded = [0u8; 8];
        file_contents_buf_padded[8 - file_contents_buf.len()..].copy_from_slice(&file_contents_buf);
        stream.write_all(&file_contents_buf_padded).unwrap();
        stream.write_all(&file_contents_encrypted).unwrap();
    }
}
