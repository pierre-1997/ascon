use anyhow::{bail, Context};
use ascon::aead128::AEAD128;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::str;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Turn debugging information on
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    cmd: Command,

    #[arg(short, long)]
    out_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Performs `Ascon-AEAD128` (en/de)cryption.
    Aead {
        ///
        key: String,
        ///
        nonce: String,
        ///
        ad: String,
        ///
        in_file: PathBuf,

        /// If given, means we are decrypting.
        tag: Option<String>,
    },
}

fn parse_hex(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    if hex_str.len() % 2 != 0 {
        bail!("Hex string length must be even");
    }

    match (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect()
    {
        Ok(v) => Ok(v),
        Err(_) => bail!("Invalid hex character."),
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.debug {
        std::env::set_var("RUST_LOG", "debug");
    }

    pretty_env_logger::init();

    match args.cmd {
        Command::Aead {
            key,
            nonce,
            ad,
            in_file,
            tag,
        } => {
            let key = parse_hex(&key).context("Parsing key hex.")?;
            anyhow::ensure!(key.len() == 16, "Key must be exactly 16 bytes long.");
            let key: [u8; 16] = key.try_into().unwrap();
            let nonce = parse_hex(&nonce).context("Parsing key hex.")?;
            anyhow::ensure!(nonce.len() == 16, "Nonce must be exactly 16 bytes long.");
            let nonce: [u8; 16] = nonce.try_into().unwrap();

            let ad = ad.as_bytes();

            let input = fs::read(&in_file).context(format!("Reading [{}]", in_file.display()))?;

            match tag {
                Some(tag) => {
                    let tag = parse_hex(&tag).context("Parsing tag.")?;
                    anyhow::ensure!(tag.len() == 16, "Tag must be exactly 16 bytes long.");
                    let tag: [u8; 16] = tag.try_into().unwrap();

                    let Some(dec) = AEAD128::decrypt(key, nonce, &ad, &input, tag) else {
                        bail!("Failed to decrypt [{}], invalid.tag.", in_file.display());
                    };
                    if let Some(out_path) = args.out_path {
                        fs::write(&out_path, dec)
                            .context(format!("Writing output to [{}]", out_path.display()))?;
                    } else {
                        match str::from_utf8(&dec) {
                            Ok(s) => {
                                println!(
                                    "Decrypted content:\n--- START ---\n{}\n--- END ---",
                                    s.chars().take(100).collect::<String>()
                                )
                            }
                            Err(_) => {
                                println!("Decrypted content:\n{:?}", dec.iter().take(100))
                            }
                        }
                    };
                }
                None => {
                    let (enc, tag) = AEAD128::encrypt(key, nonce, ad, &input);

                    if let Some(out_path) = args.out_path {
                        fs::write(&out_path, enc)
                            .context(format!("Writing output to [{}]", out_path.display()))?;
                    } else {
                        match str::from_utf8(&enc) {
                            Ok(s) => {
                                println!(
                                    "Decrypted content:\n--- START ---\n{}...\n--- END ---",
                                    s.chars().take(100).collect::<String>()
                                )
                            }
                            Err(_) => {
                                println!("Decrypted content:\n{:?}...", enc.iter().take(100))
                            }
                        }
                    };

                    println!(
                        "Encrypted tag: [{}]",
                        tag.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<String>>()
                            .join("")
                    );
                }
            }
        }
    }

    Ok(())
}
