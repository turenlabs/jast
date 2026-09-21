use super::*;
#[test]
fn cancellation_and_terminal_publication_have_one_order() {
    let (_dir, app, scan, finding) = fixture();
    let (_, plan) = app.prepare_investigation(&finding).unwrap();
    let id = app.persist_investigation(&scan, &plan).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    *lock(&app.active).unwrap() = Some((id.clone(), flag.clone()));
    app.cancel_investigation_job(&id).unwrap();
    let request = investigation::make_request(&plan, &[], 1, &BTreeMap::new()).unwrap();
    let value = response(&request, "stop_supported", 0.9, 0.9);
    let decision = investigation::parse_decision(&value, &request).unwrap();
    assert!(
        app.save_investigation_step(&id, 1, &request.to_string(), &value, &decision, &flag)
            .unwrap()
    );
    let saved = app.investigation(&id).unwrap();
    assert_eq!(saved.status, "cancelled");
    assert_eq!(saved.outcome.as_deref(), Some("unresolved"));
    let done = app.persist_investigation(&scan, &plan).unwrap();
    flag.store(false, Ordering::SeqCst);
    *lock(&app.active).unwrap() = Some((done.clone(), flag.clone()));
    assert!(
        app.save_investigation_step(&done, 1, &request.to_string(), &value, &decision, &flag)
            .unwrap()
    );
    assert!(app.cancel_investigation_job(&done).is_err());
    assert!(!flag.load(Ordering::SeqCst));
    assert_eq!(
        app.investigation(&done).unwrap().outcome.as_deref(),
        Some("model_supported")
    );
}
fn fixture() -> (tempfile::TempDir, AppState, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).unwrap();
    for (name, code) in [
        (
            "entry.py",
            "def handler(user_input):\n    return database_query(user_input)\n",
        ),
        (
            "database.py",
            "def database_query(value):\n    return connection.execute(value)\n",
        ),
        (
            "guard.py",
            "def audit(value):\n    return database_query(value)\n",
        ),
    ] {
        fs::write(repo.join(name), code).unwrap();
    }
    let snapshot = scanner::inventory(&repo, &[]).unwrap();
    let app = AppState::open(&dir.path().join("data")).unwrap();
    let scan = app.persist_snapshot(&snapshot).unwrap();
    for chunk in app.pending(&scan).unwrap() {
        let request: Value = serde_json::from_str(&chunk.request_json).unwrap();
        let mut answers=scanner::synthetic_answers(&request,0.1);
        if chunk.path=="entry.py"{answers.insert("sqli".into(),json!({"type":"noul","noul":0.9}));}
        let response = json!({"model":scanner::MODEL,"answers":answers,"usage":{"input_tokens":1,"output_tokens":1}});
        app.commit_result(
            &chunk,
            &response,
            &scanner::parse_response(&response, &request).unwrap(),
            false,
            scanner::THRESHOLD,
        )
        .unwrap();
    }
    let finding = app.detail(&scan).unwrap().findings[0].id.clone();
    (dir, app, scan, finding)
}
fn response(request: &Value, action: &str, support: f64, sufficient: f64) -> Value {
    let probabilities = request["questions"]["next_action"]["criteria"]
        .as_object()
        .unwrap()
        .keys()
        .map(|key| (key.clone(), json!(if key == action { 1.0 } else { 0.0 })))
        .collect::<serde_json::Map<_, _>>();
    let mut answers = json!({"next_action":{"type":"choice","choice":action,"probabilities":probabilities,"confidence":0.9},"claim_supported":{"type":"noul","noul":support},"evidence_sufficient":{"type":"noul","noul":sufficient}});
    for key in request["questions"].as_object().unwrap().keys() {
        if key.starts_with("relevance:") {
            answers[key] = json!({"type":"noul","noul":0.9});
        }
    }
    json!({"model":scanner::MODEL,"usage":{"input_tokens":1,"output_tokens":1},"answers":answers})
}
#[test]
fn three_round_evidence_loop_preserves_original_candidate_and_exports_trace() {
    let (_dir, app, scan, finding) = fixture();
    let (owner, plan) = app.prepare_investigation(&finding).unwrap();
    assert_eq!(owner, scan);
    assert_eq!(plan.candidates.len(), 2);
    let id = app.persist_investigation(&scan, &plan).unwrap();
    let mut calls = 0;
    app.investigate_with(&id, &AtomicBool::new(false), |body| {
        calls += 1;
        let request: Value = serde_json::from_str(body)?;
        assert_eq!(
            request["state"]["inspected_evidence"]
                .as_array()
                .unwrap()
                .len(),
            calls - 1
        );
        let action = if calls < 3 {
            request["questions"]["next_action"]["criteria"]
                .as_object()
                .unwrap()
                .keys()
                .find(|id| id.starts_with("read:"))
                .unwrap()
                .clone()
        } else {
            "stop_not_supported".into()
        };
        Ok(Some(response(&request, &action, 0.1, 0.9)))
    })
    .unwrap();
    assert_eq!(calls, 3);
    let saved = app.investigation(&id).unwrap();
    assert_eq!(saved.status, "completed");
    assert_eq!(saved.outcome.as_deref(), Some("model_not_supported"));
    assert_eq!(saved.steps.len(), 3);
    for step in &saved.steps {
        assert_eq!(
            step.request_sha256,
            format!("{:x}", Sha256::digest(step.request_json.as_bytes()))
        );
    }
    let original = app.detail(&scan).unwrap();
    assert_eq!(original.findings[0].probability, 0.9);
    assert!(!original.findings[0].dismissed);
    assert_eq!(
        app.export_data(&scan).unwrap()["investigations"][0]["steps"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}
#[test]
fn cancellation_before_and_after_response_never_continues() {
    let (_dir, app, scan, finding) = fixture();
    let (_, plan) = app.prepare_investigation(&finding).unwrap();
    let id = app.persist_investigation(&scan, &plan).unwrap();
    let cancel = AtomicBool::new(true);
    app.investigate_with(&id, &cancel, |_| {
        panic!("No request allowed after cancellation")
    })
    .unwrap();
    assert_eq!(app.investigation(&id).unwrap().status, "cancelled");
    let id = app.persist_investigation(&scan, &plan).unwrap();
    cancel.store(false, Ordering::SeqCst);
    let mut calls = 0;
    app.investigate_with(&id, &cancel, |body| {
        calls += 1;
        cancel.store(true, Ordering::SeqCst);
        Ok(Some(response(
            &serde_json::from_str(body)?,
            "stop_supported",
            0.9,
            0.9,
        )))
    })
    .unwrap();
    let result = app.investigation(&id).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(result.steps.len(), 1);
    assert_eq!(result.status, "cancelled");
    assert_eq!(result.outcome.as_deref(), Some("unresolved"));
}
#[test]
fn plans_use_stored_source_from_same_scan_and_survive_interruption() {
    let (dir, app, scan, finding) = fixture();
    let other = dir.path().join("other");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("foreign.py"), "database_query(foreign_secret)\n").unwrap();
    let foreign = app
        .persist_snapshot(&scanner::inventory(&other, &[]).unwrap())
        .unwrap();
    fs::write(
        dir.path().join("repo/database.py"),
        "changed_after_scan()\n",
    )
    .unwrap();
    let (_, plan) = app.prepare_investigation(&finding).unwrap();
    assert!(
        plan.candidates
            .iter()
            .any(|c| c.code.contains("connection.execute"))
    );
    assert!(
        plan.candidates
            .iter()
            .all(|c| !c.code.contains("changed_after_scan") && !c.code.contains("foreign_secret"))
    );
    let id = app.persist_investigation(&scan, &plan).unwrap();
    drop(app);
    let reopened = AppState::open(&dir.path().join("data")).unwrap();
    let saved = reopened.investigation(&id).unwrap();
    assert_eq!(saved.status, "interrupted");
    assert_eq!(saved.outcome.as_deref(), Some("unresolved"));
    assert!(
        reopened.export_data(&foreign).unwrap()["investigations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn missing_evidence_and_invalid_actions_do_not_claim_success() {
    let (_dir, app, scan, finding) = fixture();
    let (_, plan) = app.prepare_investigation(&finding).unwrap();
    let id = app.persist_investigation(&scan, &plan).unwrap();
    app.investigate_with(&id, &AtomicBool::new(false), |body| {
        Ok(Some(response(
            &serde_json::from_str(body)?,
            "stop_supported",
            0.9,
            0.1,
        )))
    })
    .unwrap();
    assert_eq!(
        app.investigation(&id).unwrap().outcome.as_deref(),
        Some("unresolved")
    );
    let invalid = app.persist_investigation(&scan, &plan).unwrap();
    let result = app.investigate_with(&invalid, &AtomicBool::new(false), |body| {
        Ok(Some(response(
            &serde_json::from_str(body)?,
            "read:../../outside",
            0.9,
            0.9,
        )))
    });
    assert!(result.is_err());
    assert!(app.investigation(&invalid).unwrap().steps.is_empty());
    assert_eq!(app.detail(&scan).unwrap().findings[0].probability, 0.9);
}
