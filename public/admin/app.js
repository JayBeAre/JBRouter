var S = null;

async function api(path, options) {
  var opts = options || {};
  opts.headers = Object.assign({"Content-Type":"application/json"}, opts.headers || {});
  var response = await fetch(path, opts);
  var data = null;
  try { data = await response.json(); } catch (_) {}
  return {ok:response.ok,status:response.status,data:data};
}

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g,function(c){
    if(c === "&") return "&amp;";
    if(c === "<") return "&lt;";
    if(c === ">") return "&gt;";
    if(c === '"') return "&quot;";
    return "&#39;";
  });
}

async function boot() {
  var r = await api("/admin/api/state");
  if(!r.ok){
    document.getElementById("app").classList.add("hide");
    document.getElementById("force").classList.add("hide");
    document.getElementById("login").classList.remove("hide");
    return;
  }
  S = r.data;
  document.getElementById("login").classList.add("hide");
  if(S.mustChangePassword){
    document.getElementById("force").classList.remove("hide");
    document.getElementById("app").classList.add("hide");
  }else{
    document.getElementById("force").classList.add("hide");
    document.getElementById("app").classList.remove("hide");
    render();
  }
}

document.getElementById("lb").onclick = async function(){
  var r = await api("/admin/api/login",{
    method:"POST",
    body:JSON.stringify({password:document.getElementById("lp").value})
  });
  var e = document.getElementById("le");
  if(!r.ok){
    e.textContent = r.data && r.data.error ? r.data.error : "Login failed.";
    return;
  }
  e.textContent = "";
  await boot();
};

document.getElementById("lp").addEventListener("keydown",function(e){
  if(e.key === "Enter") document.getElementById("lb").click();
});

document.getElementById("fb").onclick = async function(){
  var currentPassword = document.getElementById("fc").value;
  var newPassword = document.getElementById("fn").value;
  var confirmPassword = document.getElementById("fx").value;
  var e = document.getElementById("fe");
  e.textContent = "";
  if(newPassword.length < 8){
    e.textContent = "New password must be at least 8 characters.";
    return;
  }
  if(newPassword !== confirmPassword){
    e.textContent = "Passwords do not match.";
    return;
  }
  var r = await api("/admin/api/change-password",{
    method:"POST",
    body:JSON.stringify({currentPassword:currentPassword,newPassword:newPassword})
  });
  if(!r.ok){
    e.textContent = r.data && r.data.error ? r.data.error : "Could not change password.";
    return;
  }
  await boot();
};

document.getElementById("logout").onclick = async function(){
  await api("/admin/api/logout",{method:"POST"});
  location.reload();
};

document.querySelectorAll(".tab").forEach(function(tab){
  tab.onclick = function(){
    document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active");});
    document.querySelectorAll(".sec").forEach(function(s){s.classList.remove("active");});
    tab.classList.add("active");
    document.getElementById(tab.dataset.s).classList.add("active");
  };
});

function poolOpts(selected){
  var html = "";
  Object.values(S.pools || {}).forEach(function(p){
    html += "<option value=\"" + esc(p.id) + "\"" + (p.id === selected ? " selected" : "") + ">" + esc(p.label) + " (" + esc(p.id) + ")</option>";
  });
  return html;
}

function providerOpts(selected){
  var html = "";
  Object.values(S.providers || {}).forEach(function(p){
    html += "<option value=\"" + esc(p.id) + "\"" + (p.id === selected ? " selected" : "") + ">" + esc(p.label) + " (" + esc(p.id) + ")</option>";
  });
  return html;
}

function render(){
  renderRoles();
  renderPools();
  renderProviders();
  renderSecurity();
  renderDebug();
}

function renderRoles(){
  var c = document.getElementById("rules");
  c.innerHTML = "";
  var rules = S.roleMap.rules || [];
  if(!rules.length){
    c.innerHTML = "<div class=\"empty\">No rules yet — every request will use the default pool below.</div>";
  }
  rules.forEach(function(r,i){
    var d = document.createElement("div");
    d.className = "row";
    d.innerHTML = "<input value=\"" + esc(r.keyword) + "\" placeholder=\"keyword\"><select>" + poolOpts(r.poolId) + "</select><button class=\"danger\">✕</button>";
    d.children[0].oninput = function(e){r.keyword=e.target.value;};
    d.children[1].onchange = function(e){r.poolId=e.target.value;};
    d.children[2].onclick = function(){S.roleMap.rules.splice(i,1);renderRoles();};
    c.appendChild(d);
  });
  var dp = document.getElementById("defaultPool");
  dp.innerHTML = poolOpts(S.roleMap.defaultPoolId);
  dp.onchange = function(e){S.roleMap.defaultPoolId=e.target.value;};
}

document.getElementById("addRule").onclick = function(){
  S.roleMap.rules.push({keyword:"",poolId:Object.keys(S.pools || {})[0] || ""});
  renderRoles();
};

document.getElementById("saveRoles").onclick = async function(){
  var r = await api("/admin/api/rolemap",{method:"POST",body:JSON.stringify(S.roleMap)});
  var msg = document.getElementById("rmmsg");
  msg.textContent = r.ok ? "Saved." : (r.data && r.data.error ? r.data.error : "Save failed.");
};

function renderPools(){
  var c = document.getElementById("poolList");
  c.innerHTML = "";
  var list = Object.values(S.pools || {});
  if(!list.length){
    c.innerHTML = "<div class=\"empty\">No pools yet. Add one below.</div>";
    return;
  }
  list.forEach(function(p){c.appendChild(poolCard(p));});
}

function poolCard(p){
  var d = document.createElement("div");
  d.className = "item";
  d.innerHTML = "<div class=\"title\"><div><input data-l value=\"" + esc(p.label) + "\"><div class=\"id\">" + esc(p.id) + "</div></div><button data-del class=\"danger\">Delete pool</button></div><div data-entries></div><button data-add class=\"secondary\" style=\"margin-top:6px\">+ Add fallback entry</button><hr class=\"sep\">";

  var fbWrap = document.createElement("div");
  var fbLabel = document.createElement("label");
  fbLabel.textContent = "If every entry above fails, fall back to pool";
  var fbSelect = document.createElement("select");
  fbSelect.innerHTML = "<option value=\"\">(none — fail normally)</option>" + poolOpts(p.fallbackPoolId || "");
  fbSelect.onchange = function(e){p.fallbackPoolId = e.target.value;};
  var fbNote = document.createElement("div");
  fbNote.className = "muted";
  fbNote.style.marginTop = "6px";
  fbNote.textContent = "Use this when a pool's entries share one rate limit so rotation alone can't help.";
  fbWrap.appendChild(fbLabel);
  fbWrap.appendChild(fbSelect);
  fbWrap.appendChild(fbNote);
  d.appendChild(fbWrap);

  var actionsWrap = document.createElement("div");
  actionsWrap.className = "actions";
  var saveBtn = document.createElement("button");
  saveBtn.className = "primary";
  saveBtn.setAttribute("data-save","");
  saveBtn.textContent = "Save pool";
  actionsWrap.appendChild(saveBtn);
  d.appendChild(actionsWrap);

  var msgEl = document.createElement("div");
  msgEl.className = "ok";
  msgEl.setAttribute("data-msg","");
  d.appendChild(msgEl);

  var list = d.querySelector("[data-entries]");

  function draw(){
    list.innerHTML = "";
    if(!(p.entries || []).length){
      list.innerHTML = "<div class=\"empty\" style=\"padding:14px;margin-bottom:10px\">No entries yet.</div>";
    }
    (p.entries || []).forEach(function(e,i){
      var r = document.createElement("div");
      r.className = "row";
      r.innerHTML = "<select>" + providerOpts(e.providerId) + "</select><input value=\"" + esc(e.model) + "\" placeholder=\"model\"><button class=\"danger\">✕</button>";
      r.children[0].onchange = function(x){e.providerId=x.target.value;};
      r.children[1].oninput = function(x){e.model=x.target.value;};
      r.children[2].onclick = function(){p.entries.splice(i,1);draw();};
      list.appendChild(r);
    });
  }

  draw();

  d.querySelector("[data-l]").oninput = function(e){p.label=e.target.value;};

  d.querySelector("[data-add]").onclick = function(){
    p.entries.push({providerId:Object.keys(S.providers || {})[0] || "",model:""});
    draw();
  };

  saveBtn.onclick = async function(){
    var r = await api("/admin/api/pools",{method:"POST",body:JSON.stringify(p)});
    msgEl.textContent = r.ok ? "Saved." : (r.data && r.data.error ? r.data.error : "Save failed.");
    if(r.ok) await refresh();
  };

  d.querySelector("[data-del]").onclick = async function(){
    if(!confirm("Delete pool \"" + p.label + "\"?")) return;
    var r = await api("/admin/api/pools/" + encodeURIComponent(p.id),{method:"DELETE"});
    if(r.ok) await refresh();
  };

  return d;
}

document.getElementById("addPool").onclick = function(){
  var id = "pool-" + Math.random().toString(36).slice(2,8);
  S.pools[id] = {id:id,label:"New Pool",entries:[],fallbackPoolId:""};
  renderPools();
  renderRoles();
};

function renderProviders(){
  var c = document.getElementById("providerList");
  c.innerHTML = "";
  var list = Object.values(S.providers || {});
  if(!list.length){
    c.innerHTML = "<div class=\"empty\">No providers yet. Add one below.</div>";
    return;
  }
  list.forEach(function(p){c.appendChild(providerCard(p));});
}

function providerCard(p){
  var d = document.createElement("div");
  d.className = "item";

  var maskedKeys = p.apiKeysMasked && p.apiKeysMasked.length ? "— " + p.apiKeysMasked.join(", ") : "";

  d.innerHTML =
    "<div class=\"title\"><div><input data-label value=\"" + esc(p.label) + "\"><div class=\"id\">" + esc(p.id) + "</div></div><button data-del class=\"danger\">Delete provider</button></div>" +
    "<div><label>Base URL</label><input data-url value=\"" + esc(p.baseUrl) + "\" placeholder=\"https://...\"></div>" +
    "<label>Extra headers (JSON object)</label><textarea data-h placeholder='{\"X-Custom-Header\":\"value\"}'></textarea>" +
    "<div class=\"muted\">Custom upstream headers. Values are stored in KV.</div>" +
    "<label>API keys (" + String(p.apiKeyCount || 0) + ") " + maskedKeys + "</label>" +
    "<textarea data-k placeholder=\"blank = keep existing; one key per line or comma-separated\"></textarea>" +
    "<div class=\"actions\"><button data-save class=\"primary\">Save provider</button></div>" +
    "<div data-msg class=\"ok\"></div>";

  d.querySelector("[data-h]").value = JSON.stringify(p.extraHeaders || {},null,2);
  d.querySelector("[data-label]").oninput = function(e){p.label=e.target.value;};
  d.querySelector("[data-url]").oninput = function(e){p.baseUrl=e.target.value;};

  d.querySelector("[data-save]").onclick = async function(){
    var headers = {};
    var text = d.querySelector("[data-h]").value.trim();

    if(text){
      try{headers=JSON.parse(text);}
      catch(e){
        d.querySelector("[data-msg]").textContent = "Invalid headers JSON: " + e.message;
        return;
      }

      if(!headers || Array.isArray(headers) || typeof headers !== "object"){
        d.querySelector("[data-msg]").textContent = "Extra headers must be a JSON object.";
        return;
      }

      var clean = {};
      Object.keys(headers).forEach(function(key){clean[String(key)] = String(headers[key]);});
      headers = clean;
    }

    var r = await api("/admin/api/providers",{
      method:"POST",
      body:JSON.stringify({
        id:p.id,
        label:p.label,
        baseUrl:p.baseUrl,
        extraHeaders:headers,
        apiKeysRaw:d.querySelector("[data-k]").value
      })
    });

    d.querySelector("[data-msg]").textContent = r.ok ? "Saved." : (r.data && r.data.error ? r.data.error : "Save failed.");
    if(r.ok) await refresh();
  };

  d.querySelector("[data-del]").onclick = async function(){
    if(!confirm("Delete provider \"" + p.label + "\"? Pools referencing it will break until you fix them.")) return;
    var r = await api("/admin/api/providers/" + encodeURIComponent(p.id),{method:"DELETE"});
    if(r.ok) await refresh();
  };

  return d;
}

document.getElementById("addProvider").onclick = function(){
  var id = "provider-" + Math.random().toString(36).slice(2,8);
  S.providers[id] = {
    id:id,
    label:"New Provider",
    baseUrl:"",
    extraHeaders:{},
    apiKeyCount:0,
    apiKeysMasked:[]
  };
  renderProviders();
  renderPools();
};

document.getElementById("sb").onclick = async function(){
  var currentPassword = document.getElementById("sc").value;
  var newPassword = document.getElementById("sn").value;
  var confirmPassword = document.getElementById("sx").value;
  var err = document.getElementById("se");
  var ok = document.getElementById("sok");

  err.textContent = "";
  ok.textContent = "";

  if(newPassword.length < 8){
    err.textContent = "New password must be at least 8 characters.";
    return;
  }

  if(newPassword !== confirmPassword){
    err.textContent = "Passwords do not match.";
    return;
  }

  var r = await api("/admin/api/change-password",{
    method:"POST",
    body:JSON.stringify({currentPassword:currentPassword,newPassword:newPassword})
  });

  if(!r.ok){
    err.textContent = r.data && r.data.error ? r.data.error : "Failed.";
    return;
  }

  document.getElementById("sc").value = "";
  document.getElementById("sn").value = "";
  document.getElementById("sx").value = "";

  ok.textContent = "Password updated. Other admin sessions are invalidated.";
};

function renderSecurity(){
  document.getElementById("raEnabled").checked = !!(S.routerAuth && S.routerAuth.enabled);
  document.getElementById("raToken").value = S.routerAuth && S.routerAuth.token ? S.routerAuth.token : "";
  document.getElementById("raStatus").textContent = (S.routerAuth && S.routerAuth.enabled) ? "Enabled — bearer token required." : "Disabled — /v1/messages is open.";
}

document.getElementById("genToken").onclick = function(){
  var bytes = crypto.getRandomValues(new Uint8Array(32));
  var hex = "";
  for(var i=0;i<bytes.length;i++){
    var h = bytes[i].toString(16);
    hex += h.length === 1 ? "0" + h : h;
  }
  document.getElementById("raToken").value = hex;
};

document.getElementById("saveRA").onclick = async function(){
  var enabled = document.getElementById("raEnabled").checked;
  var token = document.getElementById("raToken").value.trim();
  var err = document.getElementById("rae");
  var ok = document.getElementById("ras");

  err.textContent = "";
  ok.textContent = "";

  var r = await api("/admin/api/router-auth",{
    method:"POST",
    body:JSON.stringify({enabled:enabled,token:token})
  });

  if(!r.ok){
    err.textContent = r.data && r.data.error ? r.data.error : "Failed.";
    return;
  }

  S.routerAuth = {enabled:enabled,token:token};
  renderSecurity();

  ok.textContent = enabled ? "Router authentication enabled." : "Router authentication disabled.";
};

function renderDebug(){
  var enabled = !!(S.debug && S.debug.enabled);
  document.getElementById("debugEnabled").checked = enabled;
  document.getElementById("debugStatus").textContent = enabled ? "Enabled — /debug is available." : "Disabled — diagnostic endpoints are unavailable.";
}

document.getElementById("saveDebug").onclick = async function(){
  var enabled = document.getElementById("debugEnabled").checked;
  var err = document.getElementById("debugError");
  var ok = document.getElementById("debugOk");
  err.textContent = "";
  ok.textContent = "";

  var r = await api("/admin/api/debug",{
    method:"POST",
    body:JSON.stringify({enabled:enabled})
  });

  if(!r.ok){
    err.textContent = r.data && r.data.error ? r.data.error : "Failed.";
    return;
  }

  S.debug = {enabled:enabled};
  renderDebug();
  ok.textContent = enabled ? "Debug mode enabled." : "Debug mode disabled.";
};

document.getElementById("openDebug").onclick = function(){
  if(!(S.debug && S.debug.enabled)) return;
  window.open("/debug","_blank");
};

async function refresh(){
  var r = await api("/admin/api/state");
  if(r.ok){
    S = r.data;
    render();
  }
}

boot();
