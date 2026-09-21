// Offline browser contract tests. All native IPC is mocked; no keys or source leave the machine.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');
let chromium;
for (const bin of process.env.PATH.split(path.delimiter)) {
  try { ({chromium} = require(require.resolve('playwright', {paths:[path.dirname(bin)]}))); break; } catch {}
}
if (!chromium) throw new Error('Run with npx --package playwright');
const root = path.resolve(__dirname, 'dist');
const server = http.createServer((req,res) => {
  const name = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const file = path.resolve(root, '.' + (name === '/' ? '/index.html' : name));
  if (!file.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
  fs.readFile(file,(err,data) => {
    if (err) { res.writeHead(404).end(); return; }
    res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'); res.end(data);
  });
});
(async()=>{
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url=`http://127.0.0.1:${server.address().port}`;
  const browser=await chromium.launch({headless:true});
  try {
    const plain=await browser.newPage();await plain.goto(url);
    await plain.getByText('Desktop required.',{exact:true}).waitFor();
    assert.equal(await plain.getByRole('button',{name:'Choose folder…'}).isDisabled(),true);
    await plain.close();
    const page=await browser.newPage({viewport:{width:1320,height:860}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.addInitScript(()=>{
      window.isTauri=true;
      const supported=['Java','Python','Go','JavaScript','TypeScript','PHP','Rust','Ruby'];
      const paths=['src/Handler.java','src/handler.py','src/handler.go','src/handler.jsx','src/handler.tsx','src/handler.php','src/handler.rs','src/handler.rb'];
      const languages=supported.map(language=>({language,files:1,chunks:1,check_count:['JavaScript','TypeScript','Rust'].includes(language)?15:14}));
      const settings={key_configured:false,key_error:null,model:'jev-1.13.0',threshold:0.5,check_count:16,supported_languages:supported,privacy_notice:'Selected source is sent to TypeSafe. Review before consent.'};
      const preview={id:'preview-1',repo_name:'sample-service',repo_path:'/fixture/sample-service',files:8,chunks:8,bytes:960,estimated_tokens:7200,exclusions:[{path:'.env',reason:'Hidden file'}],excluded_count:3,unsupported_count:2,limit_reached:true,limit_reasons:['Fixture region limit reached'],exclusion_reasons:{'Hidden file':1,'Fixture region limit reached':2},checks:['SQL injection','OS command injection','SSRF','Code injection','Unsafe deserialization','Prototype pollution','Unsafe memory'],languages,warnings:['Referenced same-repository source and configuration may be embedded as bounded helpers.'],regions:languages.map((l,i)=>({id:'region-'+i,path:paths[i],start_line:1,end_line:3,language:l.language,check_count:l.check_count})),context_files:2};
      const coverage={included_files:preview.files,planned_regions:preview.chunks,excluded_count:preview.excluded_count,unsupported_count:preview.unsupported_count,limit_reached:preview.limit_reached,limit_reasons:preview.limit_reasons,exclusion_reasons:preview.exclusion_reasons,exclusions:preview.exclusions,warnings:preview.warnings,context_policy:'Whole files when they fit; otherwise byte-bounded regions. Referenced same-repository source/configuration may be embedded (bounded). Cross-file taint tracking is not performed.',context_files:preview.context_files};
      const legacy={id:'legacy-1',repo_name:'legacy-service',repo_path:'/fixture/legacy',status:'completed',total:1,completed:1,cached:0,findings:0,coverage:null,uncertain_regions:1,created_at:1789600000,error:null};
      const evidence={path:'src/handler.py',language:'Python',start_line:1,end_line:3,code:'def handler():\n marker = "</code><script>window.__pwned=true</script>"\n return marker',request_json:'{"model":"jev-1.13.0","state":{"language":"Python","code":"fixture"}}',response_json:'{"answers":{"sqli":{"noul":0.91}}}'};
      let scan=null, dismissed=false;
      const investigations=[];
      const clone=value=>structuredClone(value);
      window.__completeInvestigation=false;
      window.__calls=[];
      window.__TAURI_INTERNALS__={invoke:async(name,args={})=>{
        window.__calls.push({name,args:name==='save_api_key'?{redacted:true}:args});
        const summary=()=>({...scan,findings:dismissed?0:1});
        if(name==='get_settings')return {...settings};
        if(name==='set_threshold'){if(typeof args.threshold!=='number'||args.threshold<0||args.threshold>1)throw Error('Threshold must be a probability between 0 and 1');settings.threshold=args.threshold;return {...settings};}
        if(name==='save_api_key'){settings.key_configured=true;return {...settings};}
        if(name==='remove_api_key'){settings.key_configured=false;return {...settings};}
        if(name==='get_active_investigation')return clone(investigations.find(i=>i.status==='running')??null);
        if(name==='list_investigations')return clone(investigations.filter(i=>i.finding_id===args.findingId).slice().reverse());
        if(name==='start_investigation'){
          if(!args.consent||args.findingId!=='finding-1'||investigations.some(i=>i.status==='running'))throw Error('Invalid investigation consent/activity');
          const target={finding_id:args.findingId,category:'sqli',label:'SQL injection',chunk:{id:'chunk-1',path:evidence.path,start_line:1,end_line:3,code:evidence.code,request_json:evidence.request_json,request_sha256:'fixture-target-hash'}};
          const item={id:'investigation-'+(investigations.length+1),scan_id:'scan-1',finding_id:args.findingId,status:'running',outcome:null,created_at:1789660000+investigations.length,max_rounds:3,error:null,steps:[],plan:{target,candidates:[{id:'context-1',source_chunk_id:'helper-1',path:'src/database.py',start_line:1,end_line:2,code:'def query(value):\n return db.execute(value)\n',request_sha256:'fixture-context-hash'}],warnings:['Lexical context candidates, not a proven call graph.']}};
          investigations.push(item);return clone(item);
        }
        if(name==='get_investigation'){
          const item=investigations.find(i=>i.id===args.investigationId);if(!item)throw Error('Investigation missing');
          if(item.status==='running'&&window.__completeInvestigation){
            item.steps=[{round:1,request_sha256:'fixture-step-1',request_json:'{"state":{"round":1}}',response_json:'{"choice":"read:context-1"}',action:'read:context-1',claim_supported:.5,evidence_sufficient:.3,action_confidence:.9},{round:2,request_sha256:'fixture-step-2',request_json:'{"state":{"round":2,"inspected_evidence":["context-1"]}}',response_json:'{"choice":"stop_not_supported"}',action:'stop_not_supported',claim_supported:.1,evidence_sufficient:.9,action_confidence:.9}];
            item.status='completed';item.outcome='model_not_supported';
          }return clone(item);
        }
        if(name==='cancel_investigation'){const item=investigations.find(i=>i.id===args.investigationId);item.status='cancelled';item.outcome='unresolved';return null;}
        if(name==='select_repository')return preview;
        if(name==='get_preview_evidence'){const region=preview.regions.find(r=>r.id===args.chunkId);return {...evidence,path:region.path,language:region.language,response_json:null};}
        if(name==='start_scan'){
          if(!args.consent||args.previewId!==preview.id)throw Error('Invalid consent');
          scan={id:'scan-1',repo_name:preview.repo_name,repo_path:preview.repo_path,status:'running',total:8,completed:1,cached:0,findings:1,coverage,uncertain_regions:1,created_at:1789660000,error:null,threshold:settings.threshold};return summary();
        }
        if(name==='list_scans')return scan?[summary(),legacy]:[legacy];
        if(name==='get_scan'&&args.scanId===legacy.id)return {scan:legacy,findings:[]};
        if(name==='get_scan')return {scan:summary(),findings:[{id:'finding-1',chunk_id:'chunk-1',path:'src/handler.py',language:'Python',start_line:1,end_line:3,category:'sqli',label:'SQL injection',severity:'high',probability:0.91,context_missing:0.65,sink:'database_query',source:'request.param',impact:2.3,priority:0.24,duplicate_of:null,dismissed}]};
        if(name==='get_evidence')return evidence;
        if(name==='get_file_view')return {path:args.path,language:'Python',regions:[{id:'chunk-1',start_line:1,end_line:3,code:evidence.code,status:'ok',cache_hit:false}]};
        if(name==='set_dismissed'){dismissed=args.dismissed;return null;}
        if(name==='cancel_scan'){scan.status='cancelled';return null;}
        if(name==='resume_scan'){if(!args.consent)throw Error('Consent required');scan.status='completed';scan.completed=8;scan.cached=1;return summary();}
        if(name==='export_scan')return '/fixture/jast-scan.json';
        throw Error('Unexpected IPC '+name);
      }};
    });
    await page.goto(url);
    await page.getByRole('button',{name:'Choose folder…'}).click();
    await page.getByText('sample-service',{exact:true}).waitFor();
    assert.equal(await page.locator('.manifest td.lang').count(),8);
    await page.getByText('Fixture region limit reached',{exact:false}).first().waitFor();
    assert.equal(await page.getByRole('button',{name:'Authorize & start scan'}).isDisabled(),true);
    await page.getByText('Inspect included source before uploading').click();
    for (const language of ['Java','Python','Go','JavaScript','TypeScript','PHP','Rust','Ruby']) {
      await page.getByRole('button',{name:new RegExp(` ${language} · L1`)}).click();
      await page.locator('.preview-code .source-title').getByText(language,{exact:true}).waitFor();
    }
    await page.getByRole('button',{name:/src\/handler\.py Python/}).click();
    await page.getByLabel('Preview source code').waitFor();
    assert.equal(await page.evaluate(()=>window.__pwned),undefined);
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    await page.getByLabel('API key',{exact:true}).fill('test-fixture-key');
    await page.getByRole('button',{name:'Save to keychain'}).click();
    await page.getByText('API key saved to the OS keychain.').waitFor();
    assert.equal(await page.getByLabel('API key',{exact:true}).inputValue(),'');
    assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length})),{local:0,session:0});
    await page.getByRole('button',{name:'New scan',exact:true}).click();
    await page.getByRole('button',{name:'Authorize & start scan'}).click();
    await page.locator('.signal-row').first().click();
    await page.locator('.source-code').waitFor();
    await page.getByText('Limited scope: inventory was cropped by limits.',{exact:true}).waitFor();
    assert.ok(await page.locator('.coverage-context').textContent().then(text=>text.includes('1 / 1')));
    await page.getByLabel('Search findings').fill('Python');
    assert.equal(await page.locator('.signal-row').count(),1);
    await page.getByLabel('Search findings').fill('Rust');
    assert.equal(await page.locator('.signal-row').count(),0);
    await page.getByLabel('Search findings').fill('');
    assert.equal(await page.evaluate(()=>window.__pwned),undefined);
    await page.getByRole('button',{name:'Dismiss',exact:true}).click();
    await page.getByText('0 results',{exact:true}).waitFor();
    await page.getByRole('checkbox',{name:'Show dismissed'}).check();
    await page.locator('.signal-row').first().click();
    await page.getByRole('button',{name:'Restore',exact:true}).click();
    await page.getByRole('button',{name:'Cancel scan'}).click();
    await page.getByRole('button',{name:'Authorize & resume scan'}).click();
    await page.locator('.scan-summary').getByText('Selected scope complete',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Evidence & investigation',exact:true}).click();
    const investigationPanel=page.getByRole('region',{name:'Candidate investigation'});
    await investigationPanel.waitFor();
    assert.equal(await investigationPanel.getByRole('button',{name:'Authorize and investigate',exact:true}).isDisabled(),true);
    await investigationPanel.getByRole('checkbox').check();
    await investigationPanel.getByRole('button',{name:'Authorize and investigate',exact:true}).click();
    await page.getByRole('button',{name:'Cancel investigation',exact:true}).waitFor();
    await page.getByRole('button',{name:'New scan',exact:true}).click();
    assert.equal(await page.getByRole('button',{name:'Choose folder…'}).isDisabled(),true);
    await page.getByRole('button',{name:'Settings',exact:true}).click();
    assert.equal(await page.getByLabel('API key',{exact:true}).isDisabled(),true);
    await page.getByRole('button',{name:'Cancel investigation',exact:true}).click();
    await page.getByRole('button',{name:/^Signals/}).click();
    await investigationPanel.getByText('Investigation cancelled',{exact:true}).waitFor();
    assert.equal(await investigationPanel.getByRole('checkbox').isChecked(),false);
    await investigationPanel.getByRole('checkbox').check();
    await investigationPanel.getByRole('button',{name:'Authorize and investigate',exact:true}).click();
    await page.evaluate(()=>{window.__completeInvestigation=true;});
    await investigationPanel.locator('.investigation-result strong').filter({hasText:'No support found in saved context'}).waitFor();
    assert.equal(await page.locator('.signal-row strong').first().textContent(),'91.0%');
    assert.equal(await page.evaluate(()=>window.__calls.filter(c=>c.name==='start_investigation').length),2);
    await investigationPanel.getByText('Technical trace',{exact:true}).click();
    await investigationPanel.getByText('Selected related snippet',{exact:true}).last().click();
    await investigationPanel.locator('.investigation-step').getByText('src/database.py:L1-2',{exact:false}).first().waitFor();
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Investigation mobile overflow');
    await page.setViewportSize({width:1320,height:860});
    await page.getByRole('button',{name:'Export JSON'}).click();
    await page.getByText('Export saved to /fixture/jast-scan.json').waitFor();
    fs.mkdirSync('jast/screenshots',{recursive:true});
    await page.screenshot({path:'jast/screenshots/findings.png'});
    await page.getByRole('button',{name:'New scan',exact:true}).click();
    await page.getByRole('button',{name:/legacy-service/}).click();
    await page.getByText('Coverage unknown: this scan predates saved inventory details',{exact:true}).waitFor();
    await page.getByText('No reported signals is not a guarantee that this code is secure.',{exact:true}).waitFor();
    await page.getByRole('button',{name:'New scan',exact:true}).click();
    await page.screenshot({path:'jast/screenshots/workspace.png'});
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mobile overflow');
    await page.screenshot({path:'jast/screenshots/mobile.png'});
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({verified:true,mode:'mocked native IPC; no cloud calls',checks:['desktop-required guard','eight-language inventory and preview','language search','key clearing/no browser storage','explicit consent','planned-scope progress and stored limits','legacy unknown coverage','missing-context count with no candidates','escaped source','dismiss/restore','cancel/resume reconsent','investigation consent','global investigation cancellation across tabs','analysis mutual exclusion','unverified investigation outcome and source trace','original candidate unchanged','export','responsive layout'],javascript_errors:errors}));
  } finally {await browser.close();server.close();}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
