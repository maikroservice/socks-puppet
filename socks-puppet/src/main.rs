use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;


const SOCKS_VERSION: u8 = 5;

#[derive(Debug)]
enum SocksError {
    IoError(io::Error),
    UnsupportedVersion,
    UnsupportedAuthMethod,
    UnsupportedCommand,
    UnsupportedAddressType,
}
impl From<io::Error> for SocksError {
    fn from(error: io::Error) -> Self {
        SocksError::IoError(error)
    }
}

fn handle_client(mut client: TcpStream) -> Result<(), SocksError> {
    // Read the SOCKS version and number of authentication methods
    let mut header = [0u8; 2];
    client.read_exact(&mut header)?;
    
    let version = header[0];
    let nmethods = header[1] as usize;
    
    if version != SOCKS_VERSION {
        return Err(SocksError::UnsupportedVersion);
    }
    
    // Read authentication methods
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods)?;
    
    // We'll only support no authentication (0x00) for now
    if !methods.contains(&0) {
        // Respond with "no acceptable methods"
        client.write_all(&[SOCKS_VERSION, 0xFF])?;
        return Err(SocksError::UnsupportedAuthMethod);
    }
    
    // Respond with "no authentication required"
    client.write_all(&[SOCKS_VERSION, 0x00])?;
    
    // Read the connection request
    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    
    let command = request[1];
    let address_type = request[3];
    
    // Parse the target address based on address_type
    let target_addr = match address_type {
        0x01 => { // IPv4
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr)?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        },
        0x03 => { // Domain name
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain)?;
            String::from_utf8_lossy(&domain).to_string()
        },
        0x04 => { // IPv6
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr)?;
            // Convert IPv6 bytes to string representation
            format!("[{}]", (0..8).map(|i| format!("{:02x}{:02x}", addr[i*2], addr[i*2+1]))
                .collect::<Vec<String>>().join(":"))
        },
        _ => return Err(SocksError::UnsupportedAddressType),
    };
    
    // Read the port (2 bytes, big-endian)
    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);

    // Add request logging
    let cmd_type = match command {
        0x01 => "CONNECT",
        0x02 => "BIND",
        0x03 => "UDP",
        _ => "UNKNOWN"
    };
    println!("New request: {} {}:{}", cmd_type, target_addr, port);

    // Now handle the command with the parsed address and port
    match command {
        0x01 => handle_connect(&mut client, &target_addr, port), // CONNECT
        0x02 => handle_bind(&mut client, &target_addr, port),    // BIND
        0x03 => handle_udp(&mut client, &target_addr, port),     // UDP ASSOCIATE
        _ => return Err(SocksError::UnsupportedCommand),
    }
}

fn handle_connect(client: &mut TcpStream, target_addr: &str, port: u16) -> Result<(), SocksError> {
    // Move existing connection logic here
    match TcpStream::connect(format!("{}:{}", target_addr, port)) {
        Ok(mut target) => {
            // Send success response
            let response = [
                SOCKS_VERSION, 0x00, 0x00, 0x01,
                0, 0, 0, 0, // Bind address (localhost)
                (port >> 8) as u8, port as u8, // Bind port
            ];
            client.write_all(&response)?;
            
            // Start bidirectional forwarding
            let mut target_clone = target.try_clone()?;
            let mut client_clone1 = client.try_clone()?;
            let mut client_clone2 = client.try_clone()?;

            let client_to_target = thread::spawn(move || {
                io::copy(&mut client_clone1, &mut target).ok();
            });
            
            let target_to_client = thread::spawn(move || {
                io::copy(&mut target_clone, &mut client_clone2).ok();
            });
            
            client_to_target.join().unwrap();
            target_to_client.join().unwrap();
            
            Ok(())
        },
        Err(e) => {
            // Send failure response
            let response = [
                SOCKS_VERSION, 0x01, 0x00, 0x01,
                0, 0, 0, 0, // Bind address
                0, 0, // Bind port
            ];
            client.write_all(&response)?;
            Err(SocksError::IoError(e))
        }
    }
}

fn handle_bind(client: &mut TcpStream, target_addr: &str, port: u16) -> Result<(), SocksError> {
    // Create a listener for incoming connections
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let bind_addr = listener.local_addr()?;
    
    // Send first reply with bound address
    let response = [
        SOCKS_VERSION, 0x00, 0x00, 0x01,
        // Convert bind_addr IP and port to bytes
        0, 0, 0, 0, // Replace with actual bound IP
        (bind_addr.port() >> 8) as u8, bind_addr.port() as u8,
    ];
    client.write_all(&response)?;
    
    // Wait for incoming connection
    if let Ok((target, _)) = listener.accept() {
        // Send second reply confirming connection
        client.write_all(&response)?;
        // Handle data transfer like in CONNECT
        // ... similar to handle_connect's forwarding logic
    }
    Ok(())
}

fn handle_udp(client: &mut TcpStream, _target_addr: &str, _port: u16) -> Result<(), SocksError> {
    // Create UDP socket
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let bind_addr = udp_socket.local_addr()?;
    
    // Send reply with UDP server address
    let response = [
        SOCKS_VERSION, 0x00, 0x00, 0x01,
        0, 0, 0, 0, // Replace with actual UDP server IP
        (bind_addr.port() >> 8) as u8, bind_addr.port() as u8,
    ];
    client.write_all(&response)?;
    
    // Handle UDP forwarding in a separate thread
    // ... UDP relay logic would go here
    
    Ok(())
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:1080")?;
    println!("SOCKS5 proxy listening on 0.0.0.0:1080");
    
    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                println!("New connection from: {}", client.peer_addr()?);
                thread::spawn(move || {
                    if let Err(e) = handle_client(client) {
                        eprintln!("Client error: {:?}", e);
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
    
    Ok(())
}