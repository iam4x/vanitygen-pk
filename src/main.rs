#![allow(unused)]

extern crate num_cpus;
extern crate regex;

use clap::Parser;
use hex::encode;
use libsecp256k1::{PublicKey, SecretKey};
use regex::Regex;
use std::{
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Arc,
    },
    thread,
};
use tiny_keccak::{Hasher, Keccak};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]

struct Args {
    #[arg(short, long, default_value_t = 0)]
    threads: u64,

    #[arg(short, long, default_value_t = false)]
    benchmark: bool,

    #[arg(short, long, default_value = "")]
    pattern: String,
}

fn main() {
    let args = Args::parse();

    let threads_count = if args.threads == 0 {
        num_cpus::get()
    } else {
        args.threads as usize
    };

    println!("Starting {} threads", threads_count);

    if args.pattern != "" {
        println!("Pattern: {}", args.pattern);
    }

    let last_max_score = Arc::new(AtomicI32::new(0));
    let ops_count = Arc::new(AtomicU64::new(0u64));

    let mut handles = vec![];
    for _i in 0..threads_count {
        let last_max_score = last_max_score.clone();
        let ops_count = ops_count.clone();
        let pattern = args.pattern.clone();
        handles.push(thread::spawn(move || {
            find_vanity_address(last_max_score, ops_count, args.benchmark, &pattern);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

fn find_vanity_address(
    last_max_score: Arc<AtomicI32>,
    ops_count: Arc<AtomicU64>,
    benchmark: bool,
    pattern: &str,
) {
    let start = std::time::Instant::now();

    let re = Regex::new(pattern).expect("Failed to compile regex");
    let mut output = [0u8; 32];

    let mut rng = fastrand::Rng::new();
    let mut entropy: [u8; 32] = [0; 32];

    loop {
        for byte in entropy.iter_mut() {
            *byte = rng.u8(..);
        }

        let secret = SecretKey::parse(&entropy).unwrap();
        let public = PublicKey::from_secret_key(&secret);
        let public = &public.serialize()[1..65];

        keccak_hash_in_place(public, &mut output);
        let score = calc_score(&output);
        let addr = encode(&output[(output.len() - 20)..]);

        if !benchmark && score >= last_max_score.load(Ordering::SeqCst) && re.is_match(&addr) {
            last_max_score.store(score, Ordering::SeqCst);

            println!("\n");
            println!("Score: {}", score);
            println!("Addr: 0x{}", addr);
            println!("Secret: {}", hex::encode(secret.serialize()));
            println!("Fount: {:?}", chrono::Utc::now());
            println!("\n");
        }

        if benchmark {
            let ops_count_val = ops_count.fetch_add(1, Ordering::SeqCst);
            if ops_count_val % 10000 == 0 {
                let ops_per_sec = ops_count_val as f64 / start.elapsed().as_secs_f64();
                println!("op/s: {}", ops_per_sec);
            }
        }
    }
}

#[inline(always)]
fn keccak_hash_in_place(input: &[u8], output: &mut [u8; 32]) {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

const NIBBLE_MASK: u8 = 0x0F;
const SCORE_FOR_LEADING_ZERO: i32 = 100;

#[inline(always)]
fn calc_score(address: &[u8]) -> i32 {
    let mut score: i32 = 0;
    let mut has_reached_non_zero = false;

    for &byte in &address[(address.len() - 20)..] {
        score += score_nibble(byte >> 4, &mut has_reached_non_zero);
        score += score_nibble(byte & NIBBLE_MASK, &mut has_reached_non_zero);
    }

    score
}

#[inline(always)]
fn score_nibble(nibble: u8, has_reached_non_zero: &mut bool) -> i32 {
    let mut local_score = 0;

    if nibble == 0 && !*has_reached_non_zero {
        local_score += SCORE_FOR_LEADING_ZERO;
    } else if nibble != 0 {
        *has_reached_non_zero = true;
    }

    local_score
}
