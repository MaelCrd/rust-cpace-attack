mod attack;
mod cpace;

use attack::simulate_attack;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage: {} <password_length> <iterations>", args[0]);
        return;
    }

    // Longueur du mot de passe à deviner
    let password_length: u32 = match args[1].parse() {
        Ok(length) if length > 0 => length,
        _ => {
            println!("La longueur du mot de passe doit être un entier positif.");
            return;
        }
    };

    // Vérification de la validité des paramètres
    if password_length <= 0 {
        println!("La longueur du mot de passe doit être supérieure à 0.");
        return;
    }

    // Nombre d'itérations de la simulation
    let iterations: i32 = match args[2].parse() {
        Ok(iter) if iter > 0 => iter,
        _ => {
            println!("Le nombre d'itérations doit être un entier positif.");
            return;
        }
    };

    if iterations <= 0 {
        println!("Le nombre d'itérations doit être supérieur à 0.");
        return;
    }
    println!(
        "Simulation de l'attaque DLOG sur CPace avec un mot de passe de longueur {} ({} iterations)...",
        password_length,
        iterations
    );

    let mut total_requests: u32 = 0;
    for _ in 0..iterations {
        match simulate_attack(password_length) {
            Ok(count) => {
                println!(
                    "Simulation terminée avec succès, nombre de requêtes à l'oracle : {}",
                    count
                );
                total_requests += count;
            }
            Err(e) => println!("\nErreur lors de la simulation: {:?}", e),
        }
    }

    // Afficher les résultats de la simulation
    println!("\n-------- Résultats de la simulation -----------");
    let average = total_requests as f64 / iterations as f64;
    println!(
        "\x1b[92mNombre moyen de requêtes à l'oracle : \x1b[1m{:.2}\x1b[0m",
        average
    );
}
