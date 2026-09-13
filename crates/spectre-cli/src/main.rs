//! Local CLI for spectre-upgrade. Two modes, no persistence, nothing logged:
//!
//!   spectre "<full name>" <site> [counter] [type_code]   derive (prompts, hidden)
//!   spectre import <path.mpjson>                          summarize an export
//!
//! `derive` reads the master password from a hidden prompt and derives in
//! process. `import` reads only metadata and needs no master password.

use spectre_core::{Identity, TYPE_LONG, TYPE_NAME};
use spectre_vault::import_mpjson;
use std::collections::BTreeMap;
use std::env;
use std::process::exit;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("import") => import_cmd(&args),
        None => usage(),
        _ => derive_cmd(&args),
    }
}

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  spectre \"<full name>\" <site> [counter] [type_code]   derive a password/login/answer");
    eprintln!("  spectre import <path.mpjson>                          summarize an export");
    eprintln!("  type_code: 16 max, 17 long (default), 18 med, 19 short, 20 basic, 21 pin, 31 phrase");
    exit(1);
}

fn derive_cmd(args: &[String]) {
    if args.len() < 3 {
        usage();
    }

    let full_name = &args[1];
    let site = &args[2];
    let counter: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let type_code: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(TYPE_LONG);

    let master = rpassword::prompt_password("Master password: ").expect("failed to read password");
    let id = Identity::new(full_name, &master);

    let password = id
        .password(site, counter, type_code)
        .unwrap_or_else(|| "<stateful: stored in app>".to_string());
    let login = id.login(site, TYPE_NAME).unwrap_or_default();
    let answer = id.answer(site, "").unwrap_or_default();

    println!("site:            {site}");
    println!("counter / type:  {counter} / {type_code}");
    println!("password:        {password}");
    println!("login (name):    {login}");
    println!("answer (generic):{answer}");
}

fn import_cmd(args: &[String]) {
    let path = match args.get(2) {
        Some(p) => p,
        None => {
            eprintln!("usage: spectre import <path.mpjson>");
            exit(1);
        }
    };

    let vault = match import_mpjson(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("import failed: {e}");
            exit(1);
        }
    };

    let mut by_type: BTreeMap<u16, usize> = BTreeMap::new();
    let mut stateful = 0usize;
    for site in vault.sites.values() {
        *by_type.entry(site.type_code).or_default() += 1;

        if site.is_stateful() {
            stateful += 1;
        }
    }

    println!("user:       {}", vault.user.full_name);
    println!("algorithm:  v{}", vault.user.algorithm);
    println!("sites:      {}", vault.sites.len());
    for (type_code, count) in &by_type {
        println!("  type {type_code:>5}: {count}");
    }
    println!("stateful (needs manual copy): {stateful}");
}
