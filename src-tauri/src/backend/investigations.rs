use super::*;
use crate::investigation::{self, Decision, Plan, Target};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(test)]
mod tests;

#[derive(Serialize)]
pub struct Investigation {
    id: String,
    scan_id: String,
    finding_id: String,
    status: String,
    outcome: Option<String>,
    created_at: u64,
    max_rounds: usize,
    error: Option<String>,
    steps: Vec<Step>,
    plan: Plan,
}
#[derive(Serialize)]
struct Step {
    round: usize,
    request_sha256: String,
    request_json: String,
    response_json: String,
    action: String,
    claim_supported: f64,
    evidence_sufficient: f64,
    action_confidence: f64,
}

pub(super) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS investigations(
      id TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES scans(id),finding_id TEXT NOT NULL REFERENCES findings(id),
      status TEXT NOT NULL,outcome TEXT,created_at INTEGER NOT NULL,error TEXT,plan_json TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS investigations_finding ON investigations(finding_id);
      CREATE TABLE IF NOT EXISTS investigation_steps(
      investigation_id TEXT NOT NULL REFERENCES investigations(id),round INTEGER NOT NULL,request_sha256 TEXT NOT NULL,
      request_json TEXT NOT NULL,response_json TEXT NOT NULL,action TEXT NOT NULL,claim_supported REAL NOT NULL,
      evidence_sufficient REAL NOT NULL,action_confidence REAL NOT NULL,PRIMARY KEY(investigation_id,round));
      UPDATE investigations SET status='interrupted',outcome='unresolved',error='JAST closed before investigation finished. Start a new investigation to continue.' WHERE status='running';")?;
    Ok(())
}

impl AppState {
    fn investigation_in(db: &Connection, id: &str) -> Result<Investigation> {
        let mut item=db.query_row("SELECT id,scan_id,finding_id,status,outcome,created_at,error,plan_json FROM investigations WHERE id=?1",[id],|r|{
            let raw:String=r.get(7)?;
            let plan=serde_json::from_str(&raw).map_err(|e|rusqlite::Error::FromSqlConversionFailure(7,rusqlite::types::Type::Text,Box::new(e)))?;
            Ok(Investigation{id:r.get(0)?,scan_id:r.get(1)?,finding_id:r.get(2)?,status:r.get(3)?,outcome:r.get(4)?,created_at:r.get(5)?,error:r.get(6)?,max_rounds:investigation::MAX_ROUNDS,steps:vec![],plan})
        }).context("Investigation not found")?;
        let mut q=db.prepare("SELECT round,request_sha256,request_json,response_json,action,claim_supported,evidence_sufficient,action_confidence FROM investigation_steps WHERE investigation_id=?1 ORDER BY round")?;
        item.steps = q
            .query_map([id], |r| {
                Ok(Step {
                    round: r.get(0)?,
                    request_sha256: r.get(1)?,
                    request_json: r.get(2)?,
                    response_json: r.get(3)?,
                    action: r.get(4)?,
                    claim_supported: r.get(5)?,
                    evidence_sufficient: r.get(6)?,
                    action_confidence: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(item)
    }

    fn investigation(&self, id: &str) -> Result<Investigation> {
        let db = lock(&self.db)?;
        Self::investigation_in(&db, id)
    }

    pub(super) fn investigations_for_scan_in(
        db: &Connection,
        scan_id: &str,
    ) -> Result<Vec<Investigation>> {
        let mut q =
            db.prepare("SELECT id FROM investigations WHERE scan_id=?1 ORDER BY created_at,rowid")?;
        let ids = q
            .query_map([scan_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter()
            .map(|id| Self::investigation_in(db, id))
            .collect()
    }

    fn prepare_investigation(&self, finding_id: &str) -> Result<(String, Plan)> {
        let db = lock(&self.db)?;
        let (scan_id,category,label,target_id)=db.query_row("SELECT c.scan_id,f.category,f.label,f.chunk_id FROM findings f JOIN chunks c ON c.id=f.chunk_id WHERE f.id=?1",[finding_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))).context("Candidate not found")?;
        let mut q=db.prepare("SELECT id,path,start_line,end_line,code,request_json,request_sha256 FROM chunks WHERE scan_id=?1 ORDER BY path,start_line")?;
        let chunks = q
            .query_map([&scan_id], |r| {
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
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        drop(db);
        let chunk = chunks
            .iter()
            .find(|c| c.id == target_id)
            .context("Candidate source is unavailable")?
            .clone();
        let plan = investigation::build_plan(
            Target {
                finding_id: finding_id.into(),
                category,
                label,
                chunk,
            },
            &chunks,
        )?;
        investigation::make_request(&plan, &[], 1, &BTreeMap::new()).context(
            "This region cannot fit the bounded investigation request; no API call was made",
        )?;
        Ok((scan_id, plan))
    }

    fn persist_investigation(&self, scan_id: &str, plan: &Plan) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        lock(&self.db)?.execute("INSERT INTO investigations(id,scan_id,finding_id,status,created_at,plan_json) VALUES(?1,?2,?3,'running',?4,?5)",params![id,scan_id,plan.target.finding_id,now(),serde_json::to_string(plan)?])?;
        Ok(id)
    }

    fn finish_investigation(
        &self,
        id: &str,
        status: &str,
        outcome: &str,
        error: Option<&str>,
    ) -> Result<()> {
        lock(&self.db)?.execute(
            "UPDATE investigations SET status=?1,outcome=?2,error=?3 WHERE id=?4",
            params![status, outcome, error, id],
        )?;
        Ok(())
    }

    fn save_investigation_step(
        &self,
        id: &str,
        round: usize,
        body: &str,
        response: &Value,
        decision: &Decision,
        cancel: &AtomicBool,
    ) -> Result<bool> {
        let mut db = lock(&self.db)?;
        let tx = db.transaction()?;
        tx.execute("INSERT INTO investigation_steps(investigation_id,round,request_sha256,request_json,response_json,action,claim_supported,evidence_sufficient,action_confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id,round,format!("{:x}",Sha256::digest(body.as_bytes())),body,serde_json::to_string(response)?,decision.action,decision.claim_supported,decision.evidence_sufficient,decision.action_confidence])?;
        // Cancellation requests take this same DB lock before setting their flag.
        // A terminal result is therefore published once, never rewritten after polling stops.
        let cancelled = cancel.load(Ordering::SeqCst);
        if cancelled {
            tx.execute("UPDATE investigations SET status='cancelled',outcome='unresolved',error='In-flight assessment saved after cancellation; no further actions taken' WHERE id=?1",[id])?;
        } else if let Some(outcome) = decision.outcome() {
            tx.execute(
                "UPDATE investigations SET status='completed',outcome=?1 WHERE id=?2",
                params![outcome, id],
            )?;
        }
        tx.commit()?;
        Ok(cancelled || decision.outcome().is_some())
    }

    fn investigate_with(
        &self,
        id: &str,
        cancel: &AtomicBool,
        mut send: impl FnMut(&str) -> Result<Option<Value>>,
    ) -> Result<()> {
        let item = self.investigation(id)?;
        ensure!(
            item.status == "running" && item.steps.is_empty(),
            "Investigation is not a fresh pending job"
        );
        let plan = item.plan;
        let mut loaded = Vec::<String>::new();
        // Round-1 relevance Nouls narrow which excerpts later rounds may offer.
        let mut relevance = BTreeMap::<String, f64>::new();
        for round in 1..=investigation::MAX_ROUNDS {
            if cancel.load(Ordering::SeqCst) {
                return self.finish_investigation(id, "cancelled", "unresolved", None);
            }
            let request = match investigation::make_request(&plan, &loaded, round, &relevance) {
                Ok(r) => r,
                Err(_) => {
                    return self.finish_investigation(
                        id,
                        "completed",
                        "unresolved",
                        Some("Evidence context budget reached; no additional API call made"),
                    );
                }
            };
            let body = serde_json::to_string(&request)?;
            let Some(response) = send(&body)? else {
                return self.finish_investigation(id, "cancelled", "unresolved", None);
            };
            let decision = investigation::parse_decision(&response, &request)?;
            if let Some(answers) = response["answers"].as_object() {
                for (key, answer) in answers {
                    if let Some(id) = key.strip_prefix("relevance:")
                        && let Some(p) = answer["noul"].as_f64()
                    {
                        relevance.insert(id.to_string(), p);
                    }
                }
            }
            if self.save_investigation_step(id, round, &body, &response, &decision, cancel)? {
                return Ok(());
            }
            let context_id = decision
                .action
                .strip_prefix("read:")
                .context("Unsupported investigation action")?;
            ensure!(
                plan.candidates.iter().any(|c| c.id == context_id)
                    && !loaded.iter().any(|id| id == context_id),
                "Invalid or repeated context choice"
            );
            loaded.push(context_id.into());
        }
        self.finish_investigation(
            id,
            "completed",
            "unresolved",
            Some("Investigation round budget exhausted"),
        )
    }

    fn cancel_investigation_job(&self, investigation_id: &str) -> Result<()> {
        let active = lock(&self.active)?;
        let Some((id, cancel)) = active.as_ref() else {
            bail!("No active investigation")
        };
        ensure!(id == investigation_id, "This investigation is not active");
        let db = lock(&self.db)?;
        let status: String = db
            .query_row("SELECT status FROM investigations WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .context("This job is not an investigation")?;
        ensure!(
            status == "running",
            "Investigation already finished; cancellation was not applied"
        );
        cancel.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn launch_investigation(self: &Arc<Self>, id: String, key: String, cancel: Arc<AtomicBool>) {
        let app = self.clone();
        thread::spawn(move || {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()?;
                    app.investigate_with(&id, &cancel, |body| {
                        evaluate_with(&client, &key, body, &cancel, |value| {
                            investigation::parse_decision(value, &serde_json::from_str(body)?)
                                .map(|_| ())
                        })
                    })
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("Investigation stopped unexpectedly")));
            if let Err(error) = result {
                let _ =
                    app.finish_investigation(&id, "failed", "unresolved", Some(&error.to_string()));
            }
            if let Ok(mut active) = lock(&app.active)
                && active.as_ref().map(|a| a.0.as_str()) == Some(&id)
            {
                *active = None;
            }
        });
    }
}

#[tauri::command]
pub async fn start_investigation(
    state: State<'_, Arc<AppState>>,
    finding_id: String,
    consent: bool,
) -> std::result::Result<Investigation, String> {
    let app = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<_> {
        ensure!(
            consent,
            "Explicit consent is required to send snapshot evidence for investigation"
        );
        let mut active = lock(&app.active)?;
        ensure!(active.is_none(), "Another scan or investigation is running");
        let (scan_id, plan) = app.prepare_investigation(&finding_id)?;
        let key = read_key()?.context("Add your Jev API key in Settings first")?;
        let id = app.persist_investigation(&scan_id, &plan)?;
        let cancel = Arc::new(AtomicBool::new(false));
        *active = Some((id.clone(), cancel.clone()));
        drop(active);
        app.launch_investigation(id.clone(), key, cancel);
        app.investigation(&id)
    })
    .await
    .map_err(|_| "Could not start investigation".to_string())?
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn get_investigation(
    state: State<'_, Arc<AppState>>,
    investigation_id: String,
) -> std::result::Result<Investigation, String> {
    state
        .investigation(&investigation_id)
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn list_investigations(
    state: State<'_, Arc<AppState>>,
    finding_id: String,
) -> std::result::Result<Vec<Investigation>, String> {
    (|| -> Result<_> {
        let db = lock(&state.db)?;
        let mut q = db.prepare(
            "SELECT id FROM investigations WHERE finding_id=?1 ORDER BY created_at DESC,rowid DESC",
        )?;
        let ids = q
            .query_map([finding_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter()
            .map(|id| AppState::investigation_in(&db, id))
            .collect::<Result<Vec<_>>>()
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn get_active_investigation(
    state: State<'_, Arc<AppState>>,
) -> std::result::Result<Option<Investigation>, String> {
    (|| -> Result<_> {
        let active = lock(&state.active)?;
        let Some((id, _)) = active.as_ref() else {
            return Ok(None);
        };
        let db = lock(&state.db)?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM investigations WHERE id=?1)",
            [id],
            |r| r.get(0),
        )?;
        if exists {
            Ok(Some(AppState::investigation_in(&db, id)?))
        } else {
            Ok(None)
        }
    })()
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn cancel_investigation(
    state: State<'_, Arc<AppState>>,
    investigation_id: String,
) -> std::result::Result<(), String> {
    state
        .cancel_investigation_job(&investigation_id)
        .map_err(|e| e.to_string())
}
