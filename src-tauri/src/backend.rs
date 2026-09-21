use crate::scanner::{self, Assessment, Chunk, Judgment, Preview, Snapshot};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::State;
use uuid::Uuid;

const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const SERVICE: &str = "ai.jast.desktop";
const ACCOUNT: &str = "jev-api-key";
pub(crate) mod investigations;

pub struct AppState {
    db: Mutex<Connection>,
    preview: Mutex<Option<Snapshot>>,
    active: Mutex<Option<(String, Arc<AtomicBool>)>>,
    _lock: File,
}

#[derive(Serialize)]
pub struct Settings {
    key_configured: bool,
    key_error: Option<String>,
    model: String,
    threshold: f64,
    check_count: usize,
    supported_languages: Vec<String>,
    privacy_notice: String,
}
#[derive(Serialize)]
pub struct ScanSummary {
    id: String,
    repo_name: String,
    repo_path: String,
    status: String,
    total: usize,
    completed: usize,
    cached: usize,
    findings: usize,
    created_at: u64,
    error: Option<String>,
    coverage: Option<Coverage>,
    uncertain_regions: usize,
    // NULL on scans from before the setting existed; they all ran 0.5.
    threshold: Option<f64>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Coverage {
    included_files: usize,
    planned_regions: usize,
    excluded_count: usize,
    unsupported_count: usize,
    limit_reached: bool,
    limit_reasons: Vec<String>,
    exclusion_reasons: std::collections::BTreeMap<String, usize>,
    exclusions: Vec<scanner::Exclusion>,
    warnings: Vec<String>,
    context_policy: String,
    #[serde(default)]
    context_files: usize,
}
#[derive(Serialize)]
pub struct Finding {
    id: String,
    chunk_id: String,
    path: String,
    language: String,
    start_line: usize,
    end_line: usize,
    category: String,
    label: String,
    severity: String,
    probability: f64,
    context_missing: f64,
    sink: Option<String>,
    source: Option<String>,
    impact: Option<f64>,
    priority: f64,
    duplicate_of: Option<String>,
    dismissed: bool,
}
#[derive(Serialize)]
pub struct ScanDetail {
    scan: ScanSummary,
    findings: Vec<Finding>,
}
#[derive(Serialize)]
pub struct Evidence {
    path: String,
    language: String,
    start_line: usize,
    end_line: usize,
    code: String,
    request_json: String,
    response_json: Option<String>,
}
#[derive(Serialize)]
pub struct FileRegion {
    id: String,
    start_line: usize,
    end_line: usize,
    code: String,
    status: String,
    cache_hit: bool,
}
#[derive(Serialize)]
pub struct FileView {
    path: String,
    language: String,
    regions: Vec<FileRegion>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| anyhow::anyhow!("Application state unavailable; restart JAST"))
}
fn key_entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|_| anyhow::anyhow!("OS credential store unavailable"))
}
fn read_key() -> Result<Option<String>> {
    match key_entry()?.get_password() {
        Ok(key) => Ok(Some(key)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => bail!("Unable to access OS keychain. Unlock it or allow JAST access."),
    }
}
// The configured candidate threshold; absent or invalid rows keep the default
// that shipped before it was configurable.
fn configured_threshold(db: &Connection) -> f64 {
    db.query_row("SELECT value FROM settings WHERE key='threshold'", [], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| v.parse::<f64>().ok())
    .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
    .unwrap_or(scanner::THRESHOLD)
}
fn settings(db: &Connection) -> Settings {
    let (key_configured, key_error) = match read_key() {
        Ok(key) => (key.is_some(), None),
        Err(e) => (false, Some(e.to_string())),
    };
    Settings { key_configured,key_error,model:scanner::MODEL.into(),threshold:configured_threshold(db),
        check_count:scanner::checks().len(),supported_languages:scanner::supported_languages(),
        privacy_notice:"Selected source, file names and context are sent to TypeSafe over HTTPS. Results and source snapshots remain in this app's local data directory. Secret detection is best-effort; review scope before consent.".into() }
}

// Composite routing weight, not a truth score: category probability scaled by
// the model's impact level (normalized to the 0-3 scale) and discounted for
// missing context. Regions without an impact answer keep a neutral 0.5 factor.
fn priority(j: &Judgment, impact: Option<f64>) -> f64 {
    let impact = impact.map(|i| (i / 3.0).clamp(0.0, 1.0)).unwrap_or(0.5);
    j.probability * impact * (1.0 - j.context_missing)
}
fn request_language(request: &str) -> String {
    serde_json::from_str::<Value>(request)
        .ok()
        .and_then(|v| v["state"]["language"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "Unknown".into())
}

impl AppState {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("instance.lock"))?;
        file.try_lock_exclusive()
            .context("JAST is already running")?;
        let db = Connection::open(dir.join("jast.sqlite"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,repo_name TEXT NOT NULL,repo_path TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,error TEXT);
            CREATE TABLE IF NOT EXISTS chunks(id TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES scans(id),path TEXT NOT NULL,start_line INTEGER NOT NULL,end_line INTEGER NOT NULL,code TEXT NOT NULL,request_json TEXT NOT NULL,request_sha256 TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',response_json TEXT,cache_hit INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS chunks_scan ON chunks(scan_id);
            CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,chunk_id TEXT NOT NULL REFERENCES chunks(id),category TEXT NOT NULL,label TEXT NOT NULL,severity TEXT NOT NULL,probability REAL NOT NULL,context_missing REAL NOT NULL,dismissed INTEGER NOT NULL DEFAULT 0,UNIQUE(chunk_id,category));
            CREATE TABLE IF NOT EXISTS cache(request_sha256 TEXT PRIMARY KEY,response_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            UPDATE scans SET status='interrupted',error='JAST closed before this scan completed. Resume the saved snapshot to continue.' WHERE status='running';")?;
        let scan_columns = db
            .prepare("PRAGMA table_info(scans)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, ddl) in [("coverage_json", "TEXT"), ("threshold", "REAL")] {
            if !scan_columns.iter().any(|c| c == name) {
                // Historical scans keep NULLs: unknown coverage and the 0.5
                // constant every pre-setting scan ran with, not new defaults.
                db.execute(&format!("ALTER TABLE scans ADD COLUMN {name} {ddl}"), [])?;
            }
        }
        let finding_columns = db
            .prepare("PRAGMA table_info(findings)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, ddl) in [
            ("sink", "TEXT"),
            ("source", "TEXT"),
            ("impact", "REAL"),
            ("priority", "REAL"),
            ("duplicate_of", "TEXT"),
        ] {
            if !finding_columns.iter().any(|c| c == name) {
                // Historical findings predate evidence pointers; NULL means unknown.
                db.execute(&format!("ALTER TABLE findings ADD COLUMN {name} {ddl}"), [])?;
            }
        }
        investigations::initialize(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            preview: Mutex::new(None),
            active: Mutex::new(None),
            _lock: file,
        })
    }

    fn idle(&self) -> Result<()> {
        ensure!(lock(&self.active)?.is_none(), "Stop the current scan first");
        Ok(())
    }

    fn summary(&self, id: &str) -> Result<ScanSummary> {
        let db = lock(&self.db)?;
        Self::summary_in(&db, id)
    }

    fn summary_in(db: &Connection, id: &str) -> Result<ScanSummary> {
        db.query_row("SELECT s.id,s.repo_name,s.repo_path,s.status,s.created_at,s.error,
            (SELECT count(*) FROM chunks WHERE scan_id=s.id),
            (SELECT count(*) FROM chunks WHERE scan_id=s.id AND status='ok'),
            (SELECT count(*) FROM chunks WHERE scan_id=s.id AND cache_hit=1),
            (SELECT count(*) FROM findings f JOIN chunks c ON c.id=f.chunk_id WHERE c.scan_id=s.id AND f.dismissed=0),
            s.coverage_json,
            (SELECT count(*) FROM chunks WHERE scan_id=s.id AND status='ok' AND json_extract(response_json,'$.answers.context_missing.noul')>=0.5),
            s.threshold
            FROM scans s WHERE s.id=?1",[id],|r| {
                let coverage = r.get::<_,Option<String>>(10)?.map(|text|serde_json::from_str::<Coverage>(&text)
                    .map_err(|e|rusqlite::Error::FromSqlConversionFailure(10,rusqlite::types::Type::Text,Box::new(e)))).transpose()?;
                Ok(ScanSummary {id:r.get(0)?,repo_name:r.get(1)?,repo_path:r.get(2)?,status:r.get(3)?,created_at:r.get(4)?,error:r.get(5)?,total:r.get(6)?,completed:r.get(7)?,cached:r.get(8)?,findings:r.get(9)?,coverage,uncertain_regions:r.get(11)?,threshold:r.get(12)?})
            }).context("Scan not found or invalid stored coverage")
    }

    fn detail(&self, id: &str) -> Result<ScanDetail> {
        let db = lock(&self.db)?;
        Self::detail_in(&db, id)
    }

    fn detail_in(db: &Connection, id: &str) -> Result<ScanDetail> {
        let scan = Self::summary_in(db, id)?;
        let mut q = db.prepare("SELECT f.id,c.id,c.path,c.start_line,c.end_line,f.category,f.label,f.severity,f.probability,f.context_missing,f.sink,f.source,f.impact,COALESCE(f.priority,f.probability),f.duplicate_of,f.dismissed FROM findings f JOIN chunks c ON c.id=f.chunk_id WHERE c.scan_id=?1 ORDER BY f.dismissed, COALESCE(f.priority,f.probability) DESC,c.path,c.start_line")?;
        let findings = q
            .query_map([id], |r| {
                Ok(Finding {
                    id: r.get(0)?,
                    chunk_id: r.get(1)?,
                    path: r.get(2)?,
                    language: scanner::language_for_path(Path::new(&r.get::<_, String>(2)?))
                        .unwrap_or("Unknown")
                        .into(),
                    start_line: r.get(3)?,
                    end_line: r.get(4)?,
                    category: r.get(5)?,
                    label: r.get(6)?,
                    severity: r.get(7)?,
                    probability: r.get(8)?,
                    context_missing: r.get(9)?,
                    sink: r.get(10)?,
                    source: r.get(11)?,
                    impact: r.get(12)?,
                    priority: r.get(13)?,
                    duplicate_of: r.get(14)?,
                    dismissed: r.get(15)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ScanDetail { scan, findings })
    }

    fn export_data(&self, id: &str) -> Result<Value> {
        // One lock covers summary, findings, and source/response rows, even during a scan.
        let db = lock(&self.db)?;
        let detail = Self::detail_in(&db, id)?;
        let mut q=db.prepare("SELECT path,start_line,end_line,request_sha256,status,request_json,response_json FROM chunks WHERE scan_id=?1 ORDER BY path,start_line")?;
        let chunks=q.query_map([id],|r|Ok(json!({"path":r.get::<_,String>(0)?,"language":request_language(&r.get::<_,String>(5)?),"start_line":r.get::<_,usize>(1)?,"end_line":r.get::<_,usize>(2)?,"request_sha256":r.get::<_,String>(3)?,"status":r.get::<_,String>(4)?,"request_json":r.get::<_,String>(5)?,"response_json":r.get::<_,Option<String>>(6)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(
            json!({"app":"JAST","version":env!("CARGO_PKG_VERSION"),"model":scanner::MODEL,"threshold":detail.scan.threshold.unwrap_or(scanner::THRESHOLD),"scope":"Completed means the selected workload finished, not a whole-repository audit. Consult scan.coverage; null means historical inventory is unknown. Findings and investigation outcomes are unverified model assessments, not established vulnerabilities.","scan":detail.scan,"findings":detail.findings,"chunks":chunks,"investigations":Self::investigations_for_scan_in(&db,id)?}),
        )
    }

    fn persist_snapshot(&self, snap: &Snapshot) -> Result<String> {
        ensure!(!snap.chunks.is_empty(), "No supported source files to scan");
        let id = Uuid::new_v4().to_string();
        let mut db = lock(&self.db)?;
        let threshold = configured_threshold(&db);
        let tx = db.transaction()?;
        let p = &snap.preview;
        let policies = snap
            .chunks
            .iter()
            .filter_map(|c| serde_json::from_str::<Value>(&c.request_json).ok())
            .filter_map(|v| v["state"]["context_policy"].as_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>();
        let coverage = Coverage {
            included_files: p.files,
            planned_regions: p.chunks,
            excluded_count: p.excluded_count,
            unsupported_count: p.unsupported_count,
            limit_reached: p.limit_reached,
            limit_reasons: p.limit_reasons.clone(),
            exclusion_reasons: p.exclusion_reasons.clone(),
            exclusions: p.exclusions.clone(),
            warnings: p.warnings.clone(),
            context_policy: policies.into_iter().collect::<Vec<_>>().join("; "),
            context_files: p.context_files,
        };
        tx.execute("INSERT INTO scans(id,repo_name,repo_path,status,created_at,coverage_json,threshold) VALUES(?1,?2,?3,'running',?4,?5,?6)",params![id,snap.preview.repo_name,snap.preview.repo_path,now(),serde_json::to_string(&coverage)?,threshold])?;
        for c in &snap.chunks {
            tx.execute("INSERT INTO chunks(id,scan_id,path,start_line,end_line,code,request_json,request_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![Uuid::new_v4().to_string(),id,c.path,c.start_line,c.end_line,c.code,c.request_json,c.request_sha256])?;
        }
        tx.commit()?;
        Ok(id)
    }

    fn pending(&self, id: &str) -> Result<Vec<Chunk>> {
        let db = lock(&self.db)?;
        let mut q = db.prepare("SELECT id,path,start_line,end_line,code,request_json,request_sha256 FROM chunks WHERE scan_id=?1 AND status!='ok' ORDER BY path,start_line")?;
        Ok(q.query_map([id], |r| {
            Ok(Chunk {
                id: r.get(0)?,
                path: r.get(1)?,
                start_line: r.get(2)?,
                end_line: r.get(3)?,
                code: r.get(4)?,
                request_json: r.get(5)?,
                request_sha256: r.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn cached(&self, hash: &str, request: &Value) -> Result<Option<Value>> {
        let db = lock(&self.db)?;
        let text: Option<String> = db
            .query_row(
                "SELECT response_json FROM cache WHERE request_sha256=?1",
                [hash],
                |r| r.get(0),
            )
            .optional()?;
        match text {
            Some(t) => {
                let value: Value = serde_json::from_str(&t)?;
                scanner::parse_response(&value, request)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn commit_result(
        &self,
        c: &Chunk,
        response: &Value,
        assessment: &Assessment,
        cached: bool,
        threshold: f64,
    ) -> Result<()> {
        let mut db = lock(&self.db)?;
        let tx = db.transaction()?;
        let json = serde_json::to_string(response)?;
        tx.execute(
            "INSERT OR REPLACE INTO cache(request_sha256,response_json) VALUES(?1,?2)",
            params![c.request_sha256, json],
        )?;
        tx.execute(
            "UPDATE chunks SET status='ok',response_json=?1,cache_hit=?2 WHERE id=?3",
            params![json, cached, c.id],
        )?;
        for j in assessment
            .judgments
            .iter()
            .filter(|j| j.probability >= threshold)
        {
            tx.execute("INSERT OR IGNORE INTO findings(id,chunk_id,category,label,severity,probability,context_missing,sink,source,impact,priority) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![Uuid::new_v4().to_string(),c.id,j.category,j.label,j.severity,j.probability,j.context_missing,assessment.sink,assessment.source,assessment.impact,priority(j,assessment.impact)])?;
        }
        tx.commit()?;
        Ok(())
    }

    // Same-file, same-category candidates whose line ranges overlap are
    // reported once: adjacent regions share up to 30 lines, so overlapping
    // ranges may flag the same weakness. Highest priority stays primary;
    // the rest keep an overlap hint, not a proven-duplicate claim.
    fn merge_overlapping(&self, scan_id: &str) -> Result<()> {
        let mut db = lock(&self.db)?;
        let rows = db
            .prepare("SELECT f.id,c.path,c.start_line,c.end_line,f.category,COALESCE(f.priority,f.probability) FROM findings f JOIN chunks c ON c.id=f.chunk_id WHERE c.scan_id=?1 ORDER BY c.path,f.category,c.start_line,f.id")?
            .query_map([scan_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, usize>(2)?,
                    r.get::<_, usize>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, f64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut updates: Vec<(String, String)> = Vec::new();
        let mut i = 0;
        while i < rows.len() {
            let mut group_end = rows[i].3;
            let mut j = i + 1;
            while j < rows.len()
                && rows[j].1 == rows[i].1
                && rows[j].4 == rows[i].4
                && rows[j].2 <= group_end
            {
                group_end = group_end.max(rows[j].3);
                j += 1;
            }
            if j - i > 1 {
                let primary = rows[i..j]
                    .iter()
                    .max_by(|a, b| {
                        a.5.partial_cmp(&b.5)
                            .unwrap_or(std::cmp::Ordering::Equal)
                            .then_with(|| b.0.cmp(&a.0))
                    })
                    .unwrap();
                for row in &rows[i..j] {
                    if row.0 != primary.0 {
                        updates.push((primary.0.clone(), row.0.clone()));
                    }
                }
            }
            i = j;
        }
        let tx = db.transaction()?;
        tx.execute("UPDATE findings SET duplicate_of=NULL WHERE chunk_id IN (SELECT id FROM chunks WHERE scan_id=?1)", [scan_id])?;
        for (primary, duplicate) in updates {
            tx.execute(
                "UPDATE findings SET duplicate_of=?1 WHERE id=?2",
                params![primary, duplicate],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn process(&self, id: &str, key: &str, cancel: &AtomicBool) -> Result<()> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        self.process_with(id, cancel, |body| evaluate(&client, key, body, cancel))
    }

    fn process_with(
        &self,
        id: &str,
        cancel: &AtomicBool,
        mut request: impl FnMut(&str) -> Result<Option<Value>>,
    ) -> Result<()> {
        // The threshold recorded when the snapshot was committed governs this
        // scan, including resumes — later setting changes never rewrite it.
        let threshold = lock(&self.db)?
            .query_row("SELECT threshold FROM scans WHERE id=?1", [id], |r| {
                r.get::<_, Option<f64>>(0)
            })
            .optional()?
            .flatten()
            .unwrap_or(scanner::THRESHOLD);
        for chunk in self.pending(id)? {
            if cancel.load(Ordering::SeqCst) {
                return Ok(());
            }
            use sha2::{Digest, Sha256};
            ensure!(
                format!("{:x}", Sha256::digest(chunk.request_json.as_bytes()))
                    == chunk.request_sha256,
                "Stored source snapshot integrity check failed"
            );
            let expected_request: Value = serde_json::from_str(&chunk.request_json)?;
            let (response, hit) = match self.cached(&chunk.request_sha256, &expected_request)? {
                Some(v) => (v, true),
                None => match request(&chunk.request_json)? {
                    Some(v) => (v, false),
                    None => return Ok(()),
                },
            };
            let assessment = scanner::parse_response(&response, &expected_request)?;
            self.commit_result(&chunk, &response, &assessment, hit, threshold)?;
        }
        self.merge_overlapping(id)?;
        Ok(())
    }

    fn launch(self: &Arc<Self>, id: String, key: String, cancel: Arc<AtomicBool>) {
        let app = self.clone();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                app.process(&id, &key, &cancel)
            }))
            .unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "Scanner stopped unexpectedly; resume to retry remaining chunks"
                ))
            });
            let remaining = app.pending(&id).map(|v| v.len()).unwrap_or(1);
            let (status, error) = match result {
                Err(e) => ("failed", Some(format!("{e:#}"))),
                Ok(()) if remaining == 0 => ("completed", None),
                Ok(()) => ("cancelled", None),
            };
            if let Ok(db) = lock(&app.db) {
                let _ = db.execute(
                    "UPDATE scans SET status=?1,error=?2 WHERE id=?3",
                    params![status, error, id],
                );
            }
            if let Ok(mut active) = lock(&app.active)
                && active.as_ref().map(|v| v.0.as_str()) == Some(&id)
            {
                *active = None;
            }
        });
    }
}

fn evaluate(
    client: &reqwest::blocking::Client,
    key: &str,
    body: &str,
    cancel: &AtomicBool,
) -> Result<Option<Value>> {
    evaluate_with(client, key, body, cancel, |value| {
        scanner::parse_response(value, &serde_json::from_str(body)?).map(|_| ())
    })
}

fn evaluate_with(
    client: &reqwest::blocking::Client,
    key: &str,
    body: &str,
    cancel: &AtomicBool,
    validate: impl Fn(&Value) -> Result<()>,
) -> Result<Option<Value>> {
    for attempt in 0..4 {
        if cancel.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let mut delay = 2_u64.pow(attempt + 1);
        let (message, retry) = match client
            .post(ENDPOINT)
            .bearer_auth(key)
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if let Some(n) = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    delay = n.clamp(1, 60);
                }
                if status.is_success() {
                    let value: Value = response.json().map_err(|_| {
                        anyhow::anyhow!("TypeSafe returned invalid JSON; resume to retry")
                    })?;
                    validate(&value)
                        .context("TypeSafe response did not match the pinned model/check schema")?;
                    return Ok(Some(value));
                }
                (
                    match status.as_u16() {
                        401 | 403 => "API key was rejected. Update it in Settings.".into(),
                        429 => "TypeSafe rate limit reached.".into(),
                        n => format!("TypeSafe returned HTTP {n}."),
                    },
                    status.as_u16() == 429 || status.is_server_error(),
                )
            }
            Err(_) => (
                "Unable to reach TypeSafe. Check your connection and resume.".into(),
                true,
            ),
        };
        if !retry || attempt == 3 {
            bail!("{message}");
        }
        for _ in 0..delay * 10 {
            if cancel.load(Ordering::SeqCst) {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    unreachable!()
}

#[tauri::command]
pub async fn get_settings(
    state: State<'_, Arc<AppState>>,
) -> std::result::Result<Settings, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<Settings> {
        Ok(settings(&*lock(&app.db)?))
    })
    .await
    .map_err(|_| "Settings unavailable".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn set_threshold(
    state: State<'_, Arc<AppState>>,
    threshold: f64,
) -> std::result::Result<Settings, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<Settings> {
        ensure!(
            threshold.is_finite() && (0.0..=1.0).contains(&threshold),
            "Threshold must be a probability between 0 and 1"
        );
        ensure!(
            lock(&app.active)?.is_none(),
            "Stop the scan or investigation before changing the threshold"
        );
        lock(&app.db)?.execute(
            "INSERT INTO settings(key,value) VALUES('threshold',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [threshold.to_string()],
        )?;
        Ok(settings(&*lock(&app.db)?))
    })
    .await
    .map_err(|_| "Settings operation failed".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn save_api_key(
    state: State<'_, Arc<AppState>>,
    key: String,
) -> std::result::Result<Settings, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<Settings> {
        let active = lock(&app.active)?;
        ensure!(
            active.is_none(),
            "Stop the scan before changing the API key"
        );
        let key = key.trim();
        ensure!(
            (8..=2048).contains(&key.len())
                && key.is_ascii()
                && !key.chars().any(char::is_whitespace),
            "Enter a valid API key without spaces"
        );
        key_entry()?
            .set_password(key)
            .map_err(|_| anyhow::anyhow!("Unable to save to OS keychain"))?;
        Ok(settings(&*lock(&app.db)?))
    })
    .await
    .map_err(|_| "Credential operation failed".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn remove_api_key(
    state: State<'_, Arc<AppState>>,
) -> std::result::Result<Settings, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<Settings> {
        let active = lock(&app.active)?;
        ensure!(
            active.is_none(),
            "Stop the scan before removing the API key"
        );
        match key_entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => (),
            Err(_) => bail!("Unable to remove key from OS keychain"),
        };
        Ok(settings(&*lock(&app.db)?))
    })
    .await
    .map_err(|_| "Credential operation failed".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn select_repository(
    state: State<'_, Arc<AppState>>,
    excluded_patterns: Vec<String>,
) -> std::result::Result<Option<Preview>, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<Option<Preview>> {
        app.idle()?;
        let Some(root) = rfd::FileDialog::new()
            .set_title("Open repository for JAST")
            .pick_folder()
        else {
            return Ok(None);
        };
        let snapshot = scanner::inventory(&root, &excluded_patterns)?;
        let preview = snapshot.preview.clone();
        *lock(&app.preview)? = Some(snapshot);
        Ok(Some(preview))
    })
    .await
    .map_err(|_| "Repository selection failed".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn start_scan(
    state: State<'_, Arc<AppState>>,
    preview_id: String,
    consent: bool,
) -> std::result::Result<ScanSummary, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<ScanSummary> {
        ensure!(consent, "Explicit upload consent is required");
        let mut active = lock(&app.active)?;
        ensure!(active.is_none(), "Another scan is running");
        let key = read_key()?.context("Add your Jev API key in Settings first")?;
        let mut snapshot = lock(&app.preview)?;
        let snap = snapshot.as_ref().context("Select a repository first")?;
        ensure!(
            snap.preview.id == preview_id,
            "Preview expired; select the repository again"
        );
        let id = app.persist_snapshot(snap)?;
        let cancel = Arc::new(AtomicBool::new(false));
        *active = Some((id.clone(), cancel.clone()));
        *snapshot = None;
        drop(active);
        drop(snapshot);
        app.launch(id.clone(), key, cancel);
        app.summary(&id)
    })
    .await
    .map_err(|_| "Could not start scan".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn list_scans(
    state: State<'_, Arc<AppState>>,
) -> std::result::Result<Vec<ScanSummary>, String> {
    (|| -> Result<_> {
        let ids = {
            let db = lock(&state.db)?;
            let mut q = db.prepare("SELECT id FROM scans ORDER BY created_at DESC,rowid DESC")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        ids.iter()
            .map(|id| state.summary(id))
            .collect::<Result<Vec<_>>>()
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn get_scan(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
) -> std::result::Result<ScanDetail, String> {
    state.detail(&scan_id).map_err(|e| e.to_string())
}
#[tauri::command]
pub fn get_evidence(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
    chunk_id: String,
) -> std::result::Result<Evidence, String> {
    (||->Result<_>{
        let db=lock(&state.db)?;
        Ok(db.query_row("SELECT path,start_line,end_line,code,request_json,response_json FROM chunks WHERE scan_id=?1 AND id=?2",params![scan_id,chunk_id],|r|Ok(Evidence{path:r.get(0)?,language:request_language(&r.get::<_,String>(4)?),start_line:r.get(1)?,end_line:r.get(2)?,code:r.get(3)?,request_json:r.get(4)?,response_json:r.get(5)?}))?)
    })().map_err(|_|"Evidence not found for this scan".into())
}
#[tauri::command]
pub fn get_file_view(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
    path: String,
) -> std::result::Result<FileView, String> {
    (|| -> Result<_> {
        let db = lock(&state.db)?;
        let mut q = db.prepare("SELECT id,start_line,end_line,code,status,cache_hit,request_json FROM chunks WHERE scan_id=?1 AND path=?2 ORDER BY start_line,end_line,rowid")?;
        let rows = q
            .query_map(params![scan_id, path], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, usize>(1)?,
                    r.get::<_, usize>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let language = rows.first().map(|r| request_language(&r.6)).unwrap_or_default();
        Ok(FileView {
            path,
            language,
            regions: rows
                .into_iter()
                .map(|(id, start_line, end_line, code, status, cache_hit, _)| FileRegion {
                    id,
                    start_line,
                    end_line,
                    code,
                    status,
                    cache_hit: cache_hit != 0,
                })
                .collect(),
        })
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn get_preview_evidence(
    state: State<'_, Arc<AppState>>,
    preview_id: String,
    chunk_id: String,
) -> std::result::Result<Evidence, String> {
    (|| -> Result<_> {
        let held = lock(&state.preview)?;
        let snapshot = held.as_ref().context("Preview expired")?;
        ensure!(snapshot.preview.id == preview_id, "Preview expired");
        let c = snapshot
            .chunks
            .iter()
            .find(|c| c.id == chunk_id)
            .context("Region not found")?;
        Ok(Evidence {
            path: c.path.clone(),
            language: request_language(&c.request_json),
            start_line: c.start_line,
            end_line: c.end_line,
            code: c.code.clone(),
            request_json: c.request_json.clone(),
            response_json: None,
        })
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn cancel_scan(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
) -> std::result::Result<(), String> {
    (|| -> Result<()> {
        let active = lock(&state.active)?;
        let Some((id, cancel)) = active.as_ref() else {
            bail!("No active scan")
        };
        ensure!(id == &scan_id, "This scan is not active");
        cancel.store(true, Ordering::SeqCst);
        Ok(())
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn resume_scan(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
    consent: bool,
) -> std::result::Result<ScanSummary, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<_> {
        ensure!(
            consent,
            "Confirm upload consent to resume the stored source snapshot"
        );
        let mut active = lock(&app.active)?;
        ensure!(active.is_none(), "Another scan is running");
        let summary = app.summary(&scan_id)?;
        ensure!(
            summary.status != "completed",
            "This scan is already complete"
        );
        let key = read_key()?.context("Add your API key in Settings first")?;
        lock(&app.db)?.execute(
            "UPDATE scans SET status='running',error=NULL WHERE id=?1",
            [&scan_id],
        )?;
        let cancel = Arc::new(AtomicBool::new(false));
        *active = Some((scan_id.clone(), cancel.clone()));
        drop(active);
        app.launch(scan_id.clone(), key, cancel);
        app.summary(&scan_id)
    })
    .await
    .map_err(|_| "Could not resume scan".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn set_dismissed(
    state: State<'_, Arc<AppState>>,
    finding_id: String,
    dismissed: bool,
) -> std::result::Result<(), String> {
    (|| -> Result<()> {
        ensure!(
            lock(&state.db)?.execute(
                "UPDATE findings SET dismissed=?1 WHERE id=?2",
                params![dismissed, finding_id]
            )? == 1,
            "Finding not found"
        );
        Ok(())
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn export_scan(
    state: State<'_, Arc<AppState>>,
    scan_id: String,
) -> std::result::Result<Option<String>, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<_> {
        app.summary(&scan_id)?;
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export JAST findings (includes source snapshots)")
            .set_file_name("jast-scan.json")
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return Ok(None);
        };
        let data = app.export_data(&scan_id)?;
        fs::write(&path, serde_json::to_vec_pretty(&data)?)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|_| "Export failed".to_string())?
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, AppState, Snapshot) {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("Example.java"), "class Example { void f() {} }\n").unwrap();
        let snap = scanner::inventory(&repo, &[]).unwrap();
        let app = AppState::open(&d.path().join("data")).unwrap();
        (d, app, snap)
    }
    #[test]
    fn snapshot_is_persisted_and_recovers_as_interrupted() {
        let (d, app, snap) = fixture();
        let id = app.persist_snapshot(&snap).unwrap();
        assert_eq!(app.pending(&id).unwrap().len(), snap.chunks.len());
        fs::write(d.path().join("repo/Example.java"), "changed after consent").unwrap();
        assert!(app.pending(&id).unwrap()[0].code.contains("class Example"));
        drop(app);
        let reopened = AppState::open(&d.path().join("data")).unwrap();
        assert_eq!(reopened.summary(&id).unwrap().status, "interrupted");
    }
    #[test]
    fn lock_rejects_second_instance() {
        let (d, _app, _) = fixture();
        assert!(AppState::open(&d.path().join("data")).is_err());
    }
    #[test]
    fn cached_results_and_findings_commit_together() {
        let (_d, app, snap) = fixture();
        let id = app.persist_snapshot(&snap).unwrap();
        let c = app.pending(&id).unwrap().remove(0);
        let req: Value = serde_json::from_str(&c.request_json).unwrap();
        let answers = scanner::synthetic_answers(&req, 0.9);
        let response = json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":1}});
        let assessment = scanner::parse_response(&response, &req).unwrap();
        app.commit_result(&c, &response, &assessment, false, scanner::THRESHOLD)
            .unwrap();
        assert!(app.pending(&id).unwrap().is_empty());
        assert!(app.cached(&c.request_sha256, &req).unwrap().is_some());
        assert_eq!(app.detail(&id).unwrap().findings.len(), assessment.judgments.len());
        app.commit_result(&c, &response, &assessment, true, scanner::THRESHOLD)
            .unwrap();
        assert_eq!(app.detail(&id).unwrap().findings.len(), assessment.judgments.len());
    }
    #[test]
    fn configured_threshold_is_recorded_per_scan_and_honored() {
        let (_d, app, snap) = fixture();
        lock(&app.db)
            .unwrap()
            .execute(
                "INSERT INTO settings(key,value) VALUES('threshold','0.95')",
                [],
            )
            .unwrap();
        let id = app.persist_snapshot(&snap).unwrap();
        assert_eq!(app.summary(&id).unwrap().threshold, Some(0.95));
        let c = app.pending(&id).unwrap().remove(0);
        let req: Value = serde_json::from_str(&c.request_json).unwrap();
        let answers = scanner::synthetic_answers(&req, 0.9);
        let response =
            json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":1}});
        let assessment = scanner::parse_response(&response, &req).unwrap();
        app.commit_result(&c, &response, &assessment, false, 0.95)
            .unwrap();
        assert!(app.detail(&id).unwrap().findings.is_empty());
        app.commit_result(&c, &response, &assessment, true, scanner::THRESHOLD)
            .unwrap();
        assert_eq!(
            app.detail(&id).unwrap().findings.len(),
            assessment.judgments.len()
        );
    }
    #[test]
    fn cancellation_sends_nothing() {
        let client = reqwest::blocking::Client::new();
        let cancelled = AtomicBool::new(true);
        assert!(
            evaluate(&client, "not-a-real-key", "{}", &cancelled)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn pipeline_cache_resume_and_export_are_consistent_without_network() {
        let (_d, app, snap) = fixture();
        let id = app.persist_snapshot(&snap).unwrap();
        let cancel = AtomicBool::new(false);
        let before = app.export_data(&id).unwrap();
        assert_eq!(before["scan"]["completed"], 0);
        let mut calls = 0;
        app.process_with(&id,&cancel,|body|{
            calls+=1;let request:Value=serde_json::from_str(body)?;assert!(request["state"]["code"].as_str().unwrap().contains("class Example"));
            let answers=scanner::synthetic_answers(&request,0.8);
            Ok(Some(json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":5,"output_tokens":12}})))
        }).unwrap();
        assert_eq!(calls, 1);
        let after = app.export_data(&id).unwrap();
        assert_eq!(after["scan"]["completed"], 1);
        assert_eq!(after["findings"].as_array().unwrap().len(), 14);
        assert_eq!(after["chunks"][0]["status"], "ok");
        assert_eq!(before["findings"].as_array().unwrap().len(), 0);
        app.process_with(&id, &cancel, |_| {
            panic!("Completed chunks must not make requests")
        })
        .unwrap();
        let second = app.persist_snapshot(&snap).unwrap();
        app.process_with(&second, &cancel, |_| {
            panic!("Matching snapshot must use cache")
        })
        .unwrap();
        assert_eq!(app.summary(&second).unwrap().cached, 1);
    }

    #[test]
    fn legacy_eleven_check_java_snapshot_remains_resumable() {
        use sha2::{Digest, Sha256};
        let (_d, app, mut snap) = fixture();
        let old_keys = [
            "sqli",
            "cmdi",
            "pathtraver",
            "ldapi",
            "xpathi",
            "xss",
            "hash",
            "crypto",
            "weakrand",
            "securecookie",
            "trustbound",
            "context_missing",
        ];
        for c in &mut snap.chunks {
            let mut request: Value = serde_json::from_str(&c.request_json).unwrap();
            request["questions"]
                .as_object_mut()
                .unwrap()
                .retain(|k, _| old_keys.contains(&k.as_str()));
            request["state"] = json!({"language":"Java","code":c.code,"start_line":c.start_line,"end_line":c.end_line,"context_policy":"Region only; no external helpers or configuration retrieved."});
            c.request_json = serde_json::to_string(&request).unwrap();
            c.request_sha256 = format!("{:x}", Sha256::digest(c.request_json.as_bytes()));
        }
        let id = app.persist_snapshot(&snap).unwrap();
        app.process_with(&id,&AtomicBool::new(false),|body|{
            let request:Value=serde_json::from_str(body)?;
            assert_eq!(request["questions"].as_object().unwrap().len(),12);
            let answers=request["questions"].as_object().unwrap().keys().map(|k|(k.clone(),json!({"type":"noul","noul":0.9}))).collect::<serde_json::Map<_,_>>();
            Ok(Some(json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":12}})))
        }).unwrap();
        let detail = app.detail(&id).unwrap();
        assert_eq!(detail.findings.len(), 11);
        assert!(detail.findings.iter().all(|f| f.language == "Java"));
        let repeat = app.persist_snapshot(&snap).unwrap();
        app.process_with(&repeat, &AtomicBool::new(false), |_| {
            panic!("Old cache must remain valid for old request")
        })
        .unwrap();
        assert_eq!(app.summary(&repeat).unwrap().cached, 1);
    }

    #[test]
    fn mixed_language_pipeline_and_exports_use_matching_packs() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        fs::create_dir(&repo).unwrap();
        for (name, code) in [
            ("A.java", "class A {}"),
            ("b.py", "print('hi')"),
            ("c.go", "package main"),
            ("d.js", "let x = 1;"),
            ("e.tsx", "const x: number = 1;"),
            ("f.php", "<?php echo 'hi';"),
            ("g.rs", "fn main() {}"),
            ("h.rb", "puts 'hi'"),
        ] {
            fs::write(repo.join(name), code).unwrap();
        }
        let snap = scanner::inventory(&repo, &[]).unwrap();
        assert_eq!(snap.preview.files, 8);
        assert_eq!(snap.preview.languages.len(), 8);
        let app = AppState::open(&d.path().join("data")).unwrap();
        let id = app.persist_snapshot(&snap).unwrap();
        let mut calls = 0;
        app.process_with(&id,&AtomicBool::new(false),|body|{
            calls+=1;let request:Value=serde_json::from_str(body)?;
            let answers=scanner::synthetic_answers(&request,0.8);
            Ok(Some(json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":16}})))
        }).unwrap();
        assert_eq!(calls, 8);
        assert_eq!(app.summary(&id).unwrap().completed, 8);
        let export = app.export_data(&id).unwrap();
        let languages = export["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["language"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(languages.len(), 8);
        assert_eq!(app.detail(&id).unwrap().findings.len(), 5 * 14 + 3 * 15);
    }

    #[test]
    fn partial_pack_response_is_not_recorded_as_success() {
        let (_d, app, snap) = fixture();
        let id = app.persist_snapshot(&snap).unwrap();
        let result=app.process_with(&id,&AtomicBool::new(false),|body|{
            let request:Value=serde_json::from_str(body)?;
            let mut answers=scanner::synthetic_answers(&request,0.1);
            answers.remove("sqli");
            Ok(Some(json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":1}})))
        });
        assert!(result.is_err());
        assert_eq!(app.summary(&id).unwrap().completed, 0);
        assert!(app.detail(&id).unwrap().findings.is_empty());
    }

    #[test]
    fn coverage_survives_reopen_and_export() {
        let (d, app, mut snap) = fixture();
        snap.preview.limit_reached = true;
        snap.preview.limit_reasons = vec!["File exceeds 1 MiB".into()];
        snap.preview.excluded_count = 1;
        snap.preview
            .exclusion_reasons
            .insert("File exceeds 1 MiB".into(), 1);
        snap.preview.exclusions.push(scanner::Exclusion {
            path: "omitted.py".into(),
            reason: "File exceeds 1 MiB".into(),
        });
        let id = app.persist_snapshot(&snap).unwrap();
        let before = app.export_data(&id).unwrap();
        assert_eq!(before["scan"]["coverage"]["limit_reached"], true);
        drop(app);
        let reopened = AppState::open(&d.path().join("data")).unwrap();
        let after = reopened.export_data(&id).unwrap();
        assert_eq!(before["scan"]["coverage"], after["scan"]["coverage"]);
        assert_eq!(after["scan"]["coverage"]["excluded_count"], 1);
        assert_eq!(
            after["scan"]["coverage"]["exclusions"][0]["path"],
            "omitted.py"
        );
        assert_eq!(after["scan"]["uncertain_regions"], 0);
    }

    #[test]
    fn old_database_migration_preserves_unknown_coverage() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("data");
        fs::create_dir(&dir).unwrap();
        let db = Connection::open(dir.join("jast.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE scans(id TEXT PRIMARY KEY,repo_name TEXT NOT NULL,repo_path TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,error TEXT); INSERT INTO scans VALUES('old','legacy','/legacy','completed',1,NULL);").unwrap();
        drop(db);
        let app = AppState::open(&dir).unwrap();
        assert!(app.summary("old").unwrap().coverage.is_none());
        assert!(app.export_data("old").unwrap()["scan"]["coverage"].is_null());
        drop(app);
        let again = AppState::open(&dir).unwrap();
        assert!(again.summary("old").unwrap().coverage.is_none());
    }

    #[test]
    fn missing_context_remains_visible_without_candidates() {
        let (_d, app, snap) = fixture();
        let id = app.persist_snapshot(&snap).unwrap();
        app.process_with(&id,&AtomicBool::new(false),|body|{
            let request:Value=serde_json::from_str(body)?;
            let mut answers=scanner::synthetic_answers(&request,0.1);
            answers.insert("context_missing".into(),json!({"type":"noul","noul":0.85}));
            Ok(Some(json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":1}})))
        }).unwrap();
        let detail = app.detail(&id).unwrap();
        assert!(detail.findings.is_empty());
        assert_eq!(detail.scan.uncertain_regions, 1);
        assert_eq!(detail.scan.completed, 1);
    }

    #[test]
    #[ignore = "Opt-in local export comparison; set JAST_AUDIT_EXPORT. Never calls the API."]
    fn audit_export_context() {
        let file = std::env::var("JAST_AUDIT_EXPORT")
            .expect("Set JAST_AUDIT_EXPORT to an existing JAST JSON export");
        let export: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        let chunks = export["chunks"].as_array().unwrap();
        let mut sources = std::collections::BTreeMap::<String, Vec<Option<String>>>::new();
        let (mut old_request_bytes, mut old_question_bytes, mut old_input_tokens) =
            (0usize, 0usize, 0u64);
        for chunk in chunks {
            let path = chunk["path"].as_str().unwrap();
            assert!(
                !path.contains('\\')
                    && Path::new(path)
                        .components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                "Unsafe export path"
            );
            let raw = chunk["request_json"].as_str().unwrap();
            let request: Value = serde_json::from_str(raw).unwrap();
            old_request_bytes += raw.len();
            old_question_bytes += serde_json::to_vec(&request["questions"]).unwrap().len();
            if let Some(raw) = chunk["response_json"].as_str() {
                let response: Value = serde_json::from_str(raw).unwrap();
                old_input_tokens += response["usage"]["input_tokens"].as_u64().unwrap_or(0);
            }
            let code = request["state"]["code"].as_str().unwrap();
            let start = chunk["start_line"].as_u64().unwrap() as usize;
            assert!(start > 0);
            let lines: Vec<_> = code.split_inclusive('\n').collect();
            assert_eq!(
                start + lines.len() - 1,
                chunk["end_line"].as_u64().unwrap() as usize
            );
            let dest = sources.entry(path.to_owned()).or_default();
            dest.resize(dest.len().max(start - 1 + lines.len()), None);
            for (i, line) in lines.into_iter().enumerate() {
                let slot = &mut dest[start - 1 + i];
                if let Some(previous) = slot {
                    assert!(previous == line, "Conflicting overlap");
                } else {
                    *slot = Some(line.to_owned());
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut unique_bytes = 0usize;
        let mut base64_bytes = 0usize;
        for (path, lines) in &sources {
            let code = lines
                .iter()
                .map(|s| s.as_deref().expect("Gap in exported source"))
                .collect::<String>();
            unique_bytes += code.len();
            base64_bytes += code.len().div_ceil(3) * 4;
            let file = dir.path().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, code).unwrap();
        }
        let snapshot = scanner::inventory(dir.path(), &[]).unwrap();
        let new_request_bytes: usize = snapshot.chunks.iter().map(|c| c.request_json.len()).sum();
        let new_question_bytes: usize = snapshot
            .chunks
            .iter()
            .map(|c| {
                let r: Value = serde_json::from_str(&c.request_json).unwrap();
                serde_json::to_vec(&r["questions"]).unwrap().len()
            })
            .sum();
        println!(
            "CONTEXT_AUDIT {}",
            json!({"exported_files":sources.len(),"new_included_files":snapshot.preview.files,"old_regions":chunks.len(),"new_regions":snapshot.chunks.len(),"old_request_bytes":old_request_bytes,"new_request_bytes":new_request_bytes,"old_question_bytes":old_question_bytes,"new_question_bytes":new_question_bytes,"unique_source_bytes":unique_bytes,"base64_source_bytes":base64_bytes,"old_api_input_tokens":old_input_tokens,"new_api_input_tokens":null,"excluded_count":snapshot.preview.excluded_count,"limit_reached":snapshot.preview.limit_reached,"api_calls":0,"note":"Byte comparison only, not tokenizer measurement or accuracy evaluation; only exported source is available."})
        );
        assert_eq!(
            snapshot.preview.files,
            sources.len(),
            "Audit lost exported files"
        );
        assert!(
            new_request_bytes < old_request_bytes,
            "Expected lower total request size on this opt-in export"
        );
    }
}
