use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hmac_sha512::{Hash, BLOCKBYTES};

use rand::{rng, Rng};
use std::convert::TryInto;
use std::io::Write;

use rayon::{prelude::*, vec};
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicUsize, Arc, Mutex};

use crate::cpace::{CPace, Error, SESSION_ID_BYTES, STEP1_PACKET_BYTES};

// Fonction pour convertir un index en mot de passe
fn index_to_password(mut index: u64, charset: &[char], length: u32) -> String {
    let base = charset.len() as u64;
    let mut password = String::with_capacity(length as usize);

    for _ in 0..length {
        password.push(charset[(index % base) as usize]);
        index /= base;
    }

    password
}

// Fonction pour calculer le nombre total de combinaisons possibles
fn total_combinations(charset_size: usize, length: u32) -> Option<u64> {
    let base = charset_size as u64;
    let mut result = 1u64;

    for _ in 0..length {
        match result.checked_mul(base) {
            Some(new_result) => result = new_result,
            None => return None, // Overflow détecté
        }
    }

    Some(result)
}

// Fonction pour formater les grands nombres
fn format_large_number(num: u64) -> String {
    match num {
        n if n >= 1_000_000_000_000_000_000 => {
            format!("{:.1} quintillions", n as f64 / 1_000_000_000_000_000_000.0)
        }
        n if n >= 1_000_000_000_000_000 => {
            format!("{:.1} billiards", n as f64 / 1_000_000_000_000_000.0)
        }
        n if n >= 1_000_000_000_000 => format!("{:.1} billions", n as f64 / 1_000_000_000_000.0),
        n if n >= 1_000_000_000 => format!("{:.1} milliards", n as f64 / 1_000_000_000.0),
        n if n >= 1_000_000 => format!("{:.1} millions", n as f64 / 1_000_000.0),
        n if n >= 1_000 => format!("{:.1} milliers", n as f64 / 1_000.0),
        n => n.to_string(),
    }
}

fn print_diff(old: &str, new: &str) {
    use difference::Changeset;
    use difference::Difference;

    let changeset = Changeset::new(old, new, "");
    for diff in changeset.diffs {
        match diff {
            Difference::Add(ref s) => print!("{}", s),
            Difference::Same(ref a) => {
                print!("\x1b[35m{}\x1b[0m", a); // Vert pour les ajouts
            }
            _ => {}
        }
    }
}

// Fonction pour dériver le point de base 'g^pw' à partir d'un mot de passe donné.
fn derive_p_base_from_password<T: AsRef<[u8]>>(
    guessed_password: &str,
    session_id: [u8; SESSION_ID_BYTES],
    id_a: &str,
    id_b: &str,
    ad: Option<T>,
) -> Result<RistrettoPoint, Error> {
    if id_a.len() > 0xff || id_b.len() > 0xff {
        return Err(Error::Overflow(
            "Les identifiants doivent avoir au plus 255 octets de long",
        ));
    }
    let zpad = [0u8; BLOCKBYTES];
    // "CPaceRistretto255-1" est DSI1, doit correspondre à la constante dans lib.rs
    let pad_len = zpad
        .len()
        .wrapping_sub("CPaceRistretto255-1".len() + guessed_password.len())
        & (zpad.len() - 1);
    let mut st = Hash::new();
    st.update("CPaceRistretto255-1"); // Constante DSI1
    st.update(guessed_password);
    st.update(&zpad[..pad_len]);
    st.update(session_id);
    st.update([id_a.len() as u8]);
    st.update(id_a);
    st.update([id_b.len() as u8]);
    st.update(id_b);
    st.update(ad.as_ref().map(|ad| ad.as_ref()).unwrap_or_default());
    let h = st.finalize();
    Ok(RistrettoPoint::from_uniform_bytes(&h))
}

// Oracle de Logarithme Discret (DLOG) simulé.
// Cet oracle simule un ordinateur quantique résolvant un DLOG.
// En réalité, c'est un algorithme complexe, mais ici, pour la simulation,
// il "connaît" les valeurs réelles (`actual_p_base_used`, `actual_r_scalar_used`)
// utilisées par la session légitime pour vérifier si la supposition est correcte.
// Il retourne `true` si la supposition de mot de passe est compatible avec les observations
// et les paramètres réels, simulant un succès DLOG. Sinon, il retourne `false`
fn simulate_dlog_oracle<T: AsRef<[u8]>>(
    guessed_password: &str,
    observed_ya_bytes: &[u8; STEP1_PACKET_BYTES - SESSION_ID_BYTES], // Le point U observé par l'attaquant (partie du paquet de l'étape 1)
    session_id: [u8; SESSION_ID_BYTES],                              // ID de session observé
    id_a: &str,                                                      // ID de l'initiateur (Alice)
    id_b: &str,                                                      // ID du répondeur (Bob)
    ad: Option<T>,                // Données additionnelles observées
    actual_r_scalar_used: Scalar, // Le scalaire 'r' réel utilisé par la session légitime
) -> (bool, String) {
    // Tente de décompresser le point U observé
    let observed_ya_decompressed = match CompressedRistretto::from_slice(observed_ya_bytes)
        .map_err(|_| Error::InvalidPublicKey)
        .and_then(|cr| cr.decompress().ok_or(Error::InvalidPublicKey))
    {
        Ok(point) => point,
        Err(_) => {
            println!("  DLOG Oracle: Échec de la décompression du point observé."); // Décommenter pour le débogage
            return (false, String::new()); // Échec de la décompression
        }
    };

    // Dérive le point de base 'g^pw_guess' basé sur le mot de passe deviné par l'attaquant
    let p_base_for_guess =
        match derive_p_base_from_password(guessed_password, session_id, id_a, id_b, ad) {
            Ok(point) => point,
            Err(_) => {
                println!("  DLOG Oracle: Erreur lors de la dérivation du point de base à partir de la supposition."); // Décommenter pour le débogage
                return (false, String::new()); // Erreur lors de la dérivation
            }
        };

    // La simulation du coeur de la vérification DLOG :
    // Si le mot de passe deviné est correct, alors 'p_base_for_guess' devrait être égal à 'actual_p_base_used'.
    // Dans ce cas, 'observed_ya_decompressed' (qui est 'actual_p_base_used * actual_r_scalar_used')
    // devrait être égal à 'p_base_for_guess * actual_r_scalar_used'.
    // Si elles correspondent, l'oracle DLOG "réussit". Sinon, il "échoue".
    // C'est ainsi que l'oracle "sait" la vérité dans cette simulation.
    let expected_ya_from_guess_and_actual_r = p_base_for_guess * actual_r_scalar_used;

    let mut observed_ya_decompressed_str = String::new();
    for byte in observed_ya_decompressed.compress().as_bytes() {
        observed_ya_decompressed_str.push_str(&format!("{:02x}", byte));
    }

    let mut expected_ya_from_guess_and_actual_r_str = String::new();
    for byte in expected_ya_from_guess_and_actual_r.compress().as_bytes() {
        expected_ya_from_guess_and_actual_r_str.push_str(&format!("{:02x}", byte));
    }

    if observed_ya_decompressed == expected_ya_from_guess_and_actual_r {
        return (true, expected_ya_from_guess_and_actual_r_str); // Oracle indique un succès (le mot de passe deviné est correct)
    } else {
        return (false, expected_ya_from_guess_and_actual_r_str); // Oracle indique un échec (le mot de passe deviné est incorrect)
    }
}

pub fn simulate_attack(
    password_length: u32, // Longueur du mot de passe à deviner
) -> Result<u32, Error> {
    // --- 1. Configuration de la simulation : Une session CPace légitime ---

    // Générer un mot de passe aléatoire de 3 caractères
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    let mut rng = rng();
    let actual_password: String = (0..password_length)
        .map(|_| charset[rng.random_range(0..charset.len())])
        .collect();

    println!("----- Observation passive et attaque DLOG -----");

    println!("Mot de passe généré : '{}'", actual_password);

    let id_client = "Alice";
    let id_server = "Bob";
    let associated_data = Some("donnees_additionnelles".as_bytes());

    // Le client initie l'étape 1, générant un paquet et son contexte interne.
    // L'output de l'étape 1 inclut le paquet observable et, pour la simulation,
    // le point de base réel et le scalaire 'r' réel utilisés.
    let client_step1_output = CPace::step1(
        actual_password.as_str(),
        id_client,
        id_server,
        associated_data,
    )
    .expect("L'étape 1 du client a échoué");

    // L'attaquant intercepte ce paquet sur le réseau.
    let observed_step1_packet = client_step1_output.packet();

    // Simulation de l'interception par un attaquant : affiche le paquet de l'étape 1
    println!(
        "Packet intercepté : '{}...'",
        observed_step1_packet
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
            .get(0..40)
            .unwrap_or("")
    );

    let observed_session_id: [u8; SESSION_ID_BYTES] = observed_step1_packet[..SESSION_ID_BYTES]
        .try_into()
        .expect("Échec de l'extraction de l'ID de session");
    let observed_ya_bytes: [u8; STEP1_PACKET_BYTES - SESSION_ID_BYTES] = observed_step1_packet
        [SESSION_ID_BYTES..]
        .try_into()
        .expect("Échec de l'extraction des octets de Ya");

    let mut observed_ya_bytes_str = String::new();
    for byte in observed_ya_bytes.iter() {
        observed_ya_bytes_str.push_str(&format!("{:02x}", byte));
    }

    // Pour la simulation, l'oracle DLOG "connaît" les valeurs réelles.
    // Dans une attaque réelle, l'attaquant ne connaîtrait PAS `actual_r_scalar`.
    let actual_r_scalar = client_step1_output.actual_r_scalar;

    // Calculer le nombre total de combinaisons possibles
    let total_passwords = match total_combinations(charset.len(), password_length) {
        Some(total) => total,
        None => {
            println!("ERREUR: Le nombre de combinaisons possibles est trop grand (overflow).");
            println!(
                "Avec {} caractères et une longueur de {}, c'est {} ^ {} combinaisons.",
                charset.len(),
                password_length,
                charset.len(),
                password_length
            );
            println!("Essayez avec un mot de passe plus court (max ~10 caractères pour 62^n).");
            return Err(Error::Overflow(
                "Le nombre de combinaisons possibles est trop grand (overflow).",
            ));
        }
    };

    println!(
        "Nombre total de mots de passe à tester : {} ({})",
        total_passwords,
        format_large_number(total_passwords)
    );

    // Affiche les détails de la session observée
    println!("\x1b[35m{}\x1b[0m", observed_ya_bytes_str);

    // Compteur thread-safe pour les requêtes à l'oracle
    let oracle_queries = Arc::new(AtomicUsize::new(0));

    // Mutex pour synchroniser l'affichage du progrès
    let progress_display = Arc::new(Mutex::new(0));

    // Recherche parallélisée avec génération à la volée
    let result: Option<(u64, String)> =
        (0..total_passwords).into_par_iter().find_map_any(|index| {
            // Générer le mot de passe à partir de l'index
            let guessed_pw = index_to_password(index, &charset, password_length);

            // Incrémenter le compteur de requêtes
            let queries_count = oracle_queries.fetch_add(1, Ordering::Relaxed) + 1;

            // L'attaquant appelle l'oracle DLOG pour chaque supposition de mot de passe.
            let dlog_result = simulate_dlog_oracle(
                &guessed_pw,
                &observed_ya_bytes,
                observed_session_id,
                id_client,
                id_server,
                associated_data,
                actual_r_scalar,
            );

            // Convertir le résultat de l'oracle en chaîne pour l'affichage
            if queries_count % 65 == 0 {
                if let Ok(mut progress) = progress_display.try_lock() {
                    print!("\r");
                    print_diff(&observed_ya_bytes_str, &dlog_result.1);
                    print!(
                        " - '{}' - {} ({} %)",
                        guessed_pw,
                        queries_count,
                        (queries_count * 100) / total_passwords as usize,
                    );
                    std::io::stdout().flush().unwrap();
                    *progress = queries_count;
                }
            }

            if dlog_result.0 {
                Some((index, dlog_result.1))
            } else {
                None
            }
        });

    // Recupère le nombre total de requêtes à l'oracle
    let total_queries = oracle_queries.load(Ordering::Relaxed);

    match result {
        // Le mot de passe a été trouvé
        Some(dlog_result) => {
            let (index, expected_ya_bytes_str) = dlog_result;
            let found_password = index_to_password(index, &charset, password_length);
            if found_password == actual_password {
                print!("\r{}\r", str::repeat(" ", 120));
                print_diff(&observed_ya_bytes_str, &expected_ya_bytes_str);
                println!("");
                return Ok(total_queries as u32);
            }
        }
        // Aucun mot de passe n'a été trouvé
        None => {
            println!(
                "\nAucun mot de passe trouvé après {} requêtes à l'oracle",
                total_queries
            );
        }
    }

    return Err(Error::NotFound(
        "Aucun mot de passe trouvé après avoir interrogé l'oracle DLOG.",
    ));
}
