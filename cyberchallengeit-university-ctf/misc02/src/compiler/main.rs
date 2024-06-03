#[cfg(target_os = "linux")]
#[cfg(not(debug_assertions))]
use debugoff;
    
use std::io::{self, Write, BufRead, BufReader};
use std::net::TcpStream;
use goldberg::{goldberg_stmts, goldberg_string};
use md5::{Md5, Digest};
use std::process;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn sign(counter: i32, chal: &Vec<u8>) -> String {
    let digest = goldberg_stmts! {{
        let mod_chal: Vec<u8> = chal.into_iter()
            .map(|b| (b.wrapping_sub(64)))
            .collect();
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(counter.to_string().as_bytes());
        concatenated.extend(mod_chal.iter().take(17).map(|&b| b as u8));
        
        Md5::digest(&concatenated)
    }};
    
    format!("{:02x}", digest)
}

fn main() -> io::Result<()> {
    let _ = goldberg_stmts! {{
        #[cfg(target_os = "linux")]
        #[cfg(not(debug_assertions))]
        debugoff::multi_ptraceme_or_die();
        let mut stream = TcpStream::connect(goldberg_string!{"nftp.challs.external.open.ecsc2024.it:38203"})?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        let fixed_vector = vec![22, 163, 9, 205, 30, 109, 176, 116, 171, 205, 149, 37, 244, 14, 183, 236, 163, 117, 79, 84, 154, 206, 45, 101, 255, 154, 219, 244, 145, 132, 173, 158];
        
        reader.read_line(&mut line)?;
        let chal: Vec<u8> = line.trim().as_bytes().to_vec();
        
        let processed: Vec<u8> = chal.iter()
            .zip(fixed_vector.iter())
            .map(|(&b, &f)| (b.wrapping_add(64)) ^ f)
            .collect();
        
        let digest = Md5::digest(&processed);
        let digest_hex = format!("{:02x}", digest);
        
        stream.write(digest_hex.as_bytes());
        stream.write(b"\n");
        stream.flush();
        
        line.clear();
        reader.read_line(&mut line)?;
        
        if line.trim() != String::from("Successfully authenticated") {
            println!("{:?}", line.trim());
            process::exit(1);
        }
        
        let mut input = String::new();
        let mut num_files: u32 = 0;
        let mut files = Vec::new();
        let mut counter = 0;

        loop {
            println!("Enter command (list, get, exit):");
            input.clear();
            io::stdin().read_line(&mut input)?;
            let command = input.trim();
            
            match command {
                "list" => {
                    println!("Listing files...");
                    let sig = sign(counter, &chal);

                    let tosend = [sig.as_bytes(), b" list"].concat();
                    let tosend = [STANDARD.encode(tosend), "\n".to_string()].concat();

                    for chunk in tosend.chars().collect::<Vec<char>>().chunks(8) {
                        stream.write(chunk.iter().collect::<String>().as_bytes());
                        stream.flush();
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }

                    line.clear();
                    reader.read_line(&mut line)?;
                    if line.trim() != String::from("Valid signature") {
                        println!("{:?}", line.trim());
                        process::exit(1);
                    }
                    counter += 1;
                    line.clear();
                    reader.read_line(&mut line)?;
                    num_files = line.trim().to_string().parse().unwrap();

                    println!("{:?} files:", num_files);
                    
                    for i in 0..num_files {
                        let mut filename = String::new();
                        reader.read_line(&mut filename)?;
                        
                        println!("{:?}. {:?}", i+1, filename.trim());
                        files.push(filename.trim().to_string());
                    }
                },
                "get" => {
                    println!("Getting files...");

                    println!("How many files?");
                    line.clear();
                    io::stdin()
                        .read_line(&mut line)
                        .expect("Failed to read");

                    let n: u32 = match line.trim().parse() {
                        Ok(num) => num,
                        Err(_) => continue,
                    };

                    if n >= num_files {
                        println!("Too many files");
                        continue;
                    }
                    else {

                        for i in 0..n {
                            let sig = sign(counter, &chal);

                            let tosend = [sig.as_bytes(), b" get ", files[i as usize].as_bytes()].concat();
                            let tosend = [STANDARD.encode(tosend), "\n".to_string()].concat();
    
                            for chunk in tosend.chars().collect::<Vec<char>>().chunks(8) {
                                stream.write(chunk.iter().collect::<String>().as_bytes());
                                stream.flush();
                                std::thread::sleep(std::time::Duration::from_millis(250));
                            }
                            
                            line.clear();
                            reader.read_line(&mut line)?;
                            if line.trim() != String::from("Valid signature") {
                                println!("{:?}", line.trim());
                                process::exit(1);
                            }
                            counter += 1;
                            
                            line.clear();
                            reader.read_line(&mut line)?;
                            println!("{:?}", line.trim());
                        }

                    }

                },
                "exit" => {
                    let sig = sign(counter, &chal);

                    let tosend = [sig.as_bytes(), b" exit"].concat();
                    let tosend = [STANDARD.encode(tosend), "\n".to_string()].concat();

                    for chunk in tosend.chars().collect::<Vec<char>>().chunks(8) {
                        stream.write(chunk.iter().collect::<String>().as_bytes());
                        stream.flush();
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }

                    line.clear();
                    reader.read_line(&mut line)?;
                    if line.trim() != String::from("Valid signature") {
                        println!("{:?}", line.trim());
                        process::exit(1);
                    }
                    break;
                },
                _ => println!("Unknown command. Please enter 'list', 'get', or 'exit'."),
            }
        }
    }};
    Ok(())
}