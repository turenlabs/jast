use super::CATEGORIES;
use std::path::Path;

pub fn supported_languages() -> Vec<String> {
    [
        "Java",
        "Python",
        "Go",
        "JavaScript",
        "TypeScript",
        "PHP",
        "Rust",
        "Ruby",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
pub fn language_for_path(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if matches!(name, "Gemfile" | "Rakefile" | "config.ru") {
        return Some("Ruby");
    }
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "java" => Some("Java"),
        "py" | "pyw" | "pyi" => Some("Python"),
        "go" => Some("Go"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" | "mts" | "cts" => Some("TypeScript"),
        "php" | "phtml" | "php5" | "php7" | "php8" => Some("PHP"),
        "rs" => Some("Rust"),
        "rb" | "rake" | "gemspec" => Some("Ruby"),
        _ => None,
    }
}
pub(super) fn profile(language: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    CATEGORIES
        .iter()
        .copied()
        .filter(|(id, _, _)| match *id {
            "prototype_pollution" => matches!(language, "JavaScript" | "TypeScript"),
            "unsafe_memory" => language == "Rust",
            _ => true,
        })
        .collect()
}
// Files that are never scanned as regions but may be embedded in a request's
// state.helpers when a region references them by name (bounded at inventory).
pub(super) fn is_context_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    // Lockfiles and generated manifests are data, not review context.
    if matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "Gemfile.lock"
            | "poetry.lock"
            | "composer.lock"
    ) {
        return false;
    }
    // *.env is excluded: the credential regex only catches quoted values, and
    // dotenv-style unquoted KEY=value files conventionally hold secrets.
    matches!(
        name.rsplit('.').next().map(|e| e.to_ascii_lowercase()),
        Some(e) if matches!(e.as_str(),
            "properties" | "xml" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "json")
    )
}
pub(super) fn generated_reason(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if name.ends_with(".min.js") || name.ends_with(".min.css") {
        Some("Minified asset excluded; not assessed")
    } else if name.ends_with(".map") {
        Some("Source map excluded; not assessed")
    } else if [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        Some("Declaration-only TypeScript excluded; not assessed")
    } else {
        None
    }
}
pub(super) fn definition(id: &str) -> &'static str {
    match id {
        "sqli" => {
            "Untrusted data alters SQL syntax at an executed query. Bound value parameters are not SQL syntax; inspect dynamic identifiers separately. Input that only selects which stored procedure or routine is invoked does not alter statement syntax by itself."
        }
        "cmdi" => {
            "Untrusted data influences an executed operating-system command unsafely: shell or interpreter syntax, executable selection, dangerous arguments or the spawned process environment. Separate arguments to a fixed trusted executable are not automatically injection; do not assume a shell interprets ordinary arguments."
        }
        "pathtraver" => {
            "Attacker-controlled input influences a filesystem path used for access, extraction or writes without effective restriction to an intended boundary. Judge actual normalization and containment; plain concatenation with a base directory is not a defense, and containment that cannot be seen still counts as absent."
        }
        "ldapi" => {
            "Untrusted data changes an LDAP filter or distinguished name. Context-appropriate escaping or binding prevents injection; URL/HTML escaping does not."
        }
        "xpathi" => {
            "Untrusted data changes an evaluated XPath expression. Bound variables prevent value injection; XML parser use alone is not XPath injection."
        }
        "xss" => {
            "Untrusted data reaches browser-interpreted HTML, attributes, scripts or URLs without encoding appropriate to that context. Escaped template text is not automatically vulnerable; inspect explicit safe/raw bypasses."
        }
        "hash" => {
            "Executed code uses a cryptographically weak digest such as MD5 or SHA-1, or an unsuitable fast hash, where security strength is expected or cannot be verified from the supplied source. Resolve the algorithm through actual branches, constants and configuration references. Non-security checksums, cache keys and fingerprints are not sufficient evidence."
        }
        "crypto" => {
            "Security-sensitive encryption uses a weak cipher, unsafe mode, predictable/reused nonce, weak key or broken authentication. Identify actual configuration and use, not merely an algorithm name; a strong cipher in an authenticated mode such as GCM or CCM with a generated key is not weak."
        }
        "weakrand" => {
            "Predictable randomness generates secrets, reset tokens, authentication values or cryptographic material. Simulations, sampling and non-secret identifiers are not security defects."
        }
        "securecookie" => {
            "A security-sensitive cookie can be sent over plaintext because Secure is absent or disabled. Account for effective framework defaults and deployment configuration; not every cookie is security-sensitive."
        }
        "trustbound" => {
            "Untrusted input becomes authoritative authentication, authorization or privileged session state without validation. Storing ordinary user data in a session alone is not a trust-boundary defect."
        }
        "ssrf" => {
            "Attacker-controlled destinations reach server-side network requests enabling access outside intended trust boundaries. Check scheme/host/IP validation, redirects and resolution; fixed trusted URLs are not SSRF."
        }
        "codei" => {
            "Untrusted data is evaluated or compiled as executable code or a server-side template program. Parsing data or invoking a fixed function is not code injection."
        }
        "deserialization" => {
            "Untrusted serialized data invokes dangerous object reconstruction, hooks or gadget behavior. Plain data parsing alone is not arbitrary code execution; require a concrete unsafe reconstruction mechanism."
        }
        "prototype_pollution" => {
            "Attacker-controlled keys such as __proto__ or constructor.prototype reach recursive merge or assignment that mutates a shared prototype with security impact. JSON parsing alone or isolated own properties on null-prototype objects are not sufficient."
        }
        "unsafe_memory" => {
            "A reachable unsafe operation violates Rust memory-safety invariants: invalid pointer dereference, out-of-bounds raw access, use-after-free, double-free, invalid aliasing or data race. An unsafe block, FFI declaration or safe bounds-checked indexing alone is NOT a defect; prove the undefined-behavior operation and violated invariant."
        }
        _ => unreachable!("fixed category metadata"),
    }
}
pub(super) fn guidance(language: &str) -> &'static str {
    match language {
        "Java" => {
            "Inspect JDBC PreparedStatement bindings versus concatenated Statement SQL; Runtime.exec/ProcessBuilder argument vectors are not shell parsing unless a shell is invoked. Check servlet output encoding and template escaping, SecureRandom versus Random for secrets, MessageDigest/Cipher parameters, HttpClient/URLConnection destinations, script engines and ObjectInputStream.readObject on untrusted objects versus plain JSON data."
        }
        "Python" => {
            "Inspect sqlite3/DB-API bound parameters, Django ORM raw SQL, Jinja2/Django autoescaping versus Markup/safe bypasses; subprocess.run/Popen with shell=False and argument lists do not invoke a shell, unlike shell=True or os.system. secrets/SystemRandom are for secrets, random is not. requests/urllib destinations, eval/exec, pickle.loads and unsafe yaml.load object constructors require scrutiny; json.loads and yaml.safe_load do not inherently execute code."
        }
        "Go" => {
            "Inspect database/sql placeholders and bound arguments, html/template contextual escaping versus text/template or template.HTML bypasses. os/exec.Command with separate arguments does not invoke a shell unless explicitly running sh -c or another interpreter. crypto/rand differs from math/rand for secrets. net/http destinations and dynamic interpreters matter; encoding/json and encoding/gob are not automatically RCE: require dangerous custom hooks or downstream behavior."
        }
        "JavaScript" | "TypeScript" => {
            "Inspect SQL driver parameter bindings, child_process.exec shell strings versus execFile/spawn argument arrays without shell:true, DOM innerHTML/document.write and template raw-output bypasses versus contextual escaping. crypto.randomBytes/webcrypto differs from Math.random for secrets. fetch/axios server-side destinations, eval/new Function/vm and unsafe object deserializers matter; JSON.parse alone is not code execution. Follow __proto__, constructor and prototype keys through recursive merges; TypeScript static types do not validate runtime input."
        }
        "PHP" => {
            "Inspect PDO/mysqli bound statements, shell_exec/exec/system command strings, htmlspecialchars with correct context versus raw template output, random_bytes/random_int versus rand/mt_rand for secrets. curl/file_get_contents remote destinations, eval and dynamic includes, and unserialize object injection via magic methods matter; json_decode alone does not reconstruct executable objects."
        }
        "Rust" => {
            "Inspect sqlx/rusqlite bound query parameters, Tera/Askama contextual escaping versus safe/raw bypasses, std::process::Command separate args (not a shell unless invoking sh -c), and rand::rngs::OsRng for secrets. reqwest destinations and actual dynamic interpreters matter. serde_json/bincode data decoding alone is not RCE; require unsafe custom reconstruction. unsafe alone is NOT a defect: prove invalid raw pointer use, lifetime/aliasing violation, out-of-bounds access or another concrete undefined-behavior operation, including FFI preconditions."
        }
        "Ruby" => {
            "Inspect ActiveRecord bound SQL versus interpolated find_by_sql, ERB/Rails escaping versus html_safe/raw, system/spawn argument arrays versus shell command strings, SecureRandom versus Random for secrets. Net::HTTP/open-uri destinations, eval/class_eval, Marshal.load and unsafe YAML.load object reconstruction matter; JSON.parse and YAML.safe_load alone are not arbitrary code execution."
        }
        _ => unreachable!("supported language"),
    }
}
