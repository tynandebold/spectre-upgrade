//! Local verification CLI. Reads the master password from a hidden prompt,
//! derives everything in-process, prints to stdout, and writes nothing.
//!
//!   spectre "<full name>" <site> [counter] [type_code]
//!
//! Use it to confirm derived values match the reference app for a real site.

use spectre_core::{Identity, TYPE_LONG, TYPE_NAME};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("usage: spectre \"<full name>\" <site> [counter] [type_code]");
        eprintln!("  type_code: 16 max, 17 long (default), 18 med, 19 short, 20 basic, 21 pin, 31 phrase");
        std::process::exit(1);
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
