const state = {
  user: null,
  csrfToken: localStorage.getItem("agp_csrf_token") || "",
  view: "portal",
};

const els = {
  pageTitle: document.getElementById("pageTitle"),
  pageSubtitle: document.getElementById("pageSubtitle"),
  loginView: document.getElementById("loginView"),
  portalView: document.getElementById("portalView"),
  adminView: document.getElementById("adminView"),
  sessionPanel: document.getElementById("sessionPanel"),
  logoutButton: document.getElementById("logoutButton"),
  loginForm: document.getElementById("loginForm"),
  loginError: document.getElementById("loginError"),
  resourceGrid: document.getElementById("resourceGrid"),
  metrics: document.getElementById("metrics"),
  adminResources: document.getElementById("adminResources"),
  resourceForm: document.getElementById("resourceForm"),
  operationOutput: document.getElementById("operationOutput"),
};

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  els.loginError.textContent = "";
  const form = new FormData(els.loginForm);
  try {
    const response = await api("/api/v1/auth/login", {
      method: "POST",
      body: {
        username: form.get("username"),
        password: form.get("password"),
      },
    });
    state.csrfToken = response.csrf_token || "";
    localStorage.setItem("agp_csrf_token", state.csrfToken);
    await bootstrap();
  } catch {
    els.loginError.textContent = "Ошибка авторизации";
  }
});

els.logoutButton.addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST", csrf: true }).catch(() => {});
  localStorage.removeItem("agp_csrf_token");
  state.user = null;
  renderLoggedOut();
});

els.resourceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.resourceForm);
  const enabled = true;
  try {
    await api("/api/v1/admin/resources", {
      method: "POST",
      csrf: true,
      body: {
        name: form.get("name"),
        public_host: form.get("public_host"),
        internal_url: form.get("internal_url"),
        enabled,
        group_ids: splitCSV(form.get("group_ids")),
        allow_cidrs: splitCSV(form.get("allow_cidrs")),
      },
    });
    els.resourceForm.reset();
    await loadAdmin();
  } catch (error) {
    els.operationOutput.textContent = `Не удалось создать ресурс: ${error.message}`;
  }
});

async function bootstrap() {
  try {
    const me = await api("/api/v1/me");
    state.user = me.user;
    renderSession(me);
    els.logoutButton.classList.remove("hidden");
    if (location.pathname.startsWith("/admin") && state.user.is_admin) {
      await setView("admin");
    } else {
      await setView("portal");
    }
  } catch {
    renderLoggedOut();
  }
}

async function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  if (!state.user) {
    renderLoggedOut();
    return;
  }
  els.loginView.classList.add("hidden");
  els.portalView.classList.toggle("hidden", view !== "portal");
  els.adminView.classList.toggle("hidden", view !== "admin");

  if (view === "admin") {
    els.pageTitle.textContent = "Админка";
    els.pageSubtitle.textContent = "Пользователи, ресурсы, аудит и Nginx";
    history.replaceState(null, "", "/admin");
    await loadAdmin();
    return;
  }

  els.pageTitle.textContent = "Портал";
  els.pageSubtitle.textContent = "Доступные внутренние ресурсы";
  history.replaceState(null, "", "/");
  await loadPortal();
}

async function loadPortal() {
  const data = await api("/api/v1/resources");
  const resources = data.resources || [];
  if (resources.length === 0) {
    els.resourceGrid.innerHTML = `<div class="muted">Нет доступных ресурсов.</div>`;
    return;
  }
  els.resourceGrid.innerHTML = resources
    .map((resource) => {
      const href = `https://${escapeHTML(resource.PublicHost)}`;
      return `
        <a class="resource-item" href="${href}">
          <strong>${escapeHTML(resource.Name)}</strong>
          <span class="muted">${escapeHTML(resource.Description || resource.PublicHost)}</span>
          <span>${escapeHTML(resource.PublicHost)}</span>
        </a>
      `;
    })
    .join("");
}

async function loadAdmin() {
  if (!state.user?.is_admin) {
    els.operationOutput.textContent = "Нет административного доступа";
    return;
  }
  const [dashboard, resources] = await Promise.all([
    api("/api/v1/admin/dashboard"),
    api("/api/v1/admin/resources"),
  ]);
  renderMetrics(dashboard);
  renderAdminResources(resources.resources || []);
}

function renderMetrics(stats) {
  els.metrics.innerHTML = `
    ${metric("Пользователи", stats.UsersCount)}
    ${metric("Сессии", stats.ActiveSessionsCount)}
    ${metric("Ресурсы", stats.ResourcesCount)}
    ${metric("Audit events", stats.AuditEventsCount)}
  `;
}

function metric(label, value) {
  return `<div class="metric"><strong>${Number(value || 0)}</strong><span class="muted">${label}</span></div>`;
}

function renderAdminResources(resources) {
  if (resources.length === 0) {
    els.adminResources.innerHTML = `<div class="muted">Ресурсы еще не созданы.</div>`;
    return;
  }
  els.adminResources.innerHTML = resources
    .map(
      (resource) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(resource.Name)}</strong>
          <div class="muted">${escapeHTML(resource.PublicHost)} -> ${escapeHTML(resource.InternalURL)}</div>
        </div>
        <div class="row-actions">
          <button class="secondary" data-action="nginx" data-id="${escapeHTML(resource.ID)}">Nginx</button>
          <button class="secondary" data-action="diag" data-id="${escapeHTML(resource.ID)}">Диагностика</button>
        </div>
      </div>
    `
    )
    .join("");
  els.adminResources.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.action === "nginx") {
        await showNginx(button.dataset.id);
      } else {
        await showDiagnostics(button.dataset.id);
      }
    });
  });
}

async function showNginx(id) {
  const data = await api(`/api/v1/admin/resources/${encodeURIComponent(id)}/nginx`);
  els.operationOutput.textContent = data.nginx.snippet;
}

async function showDiagnostics(id) {
  const data = await api(`/api/v1/admin/resources/${encodeURIComponent(id)}/diagnostics`, {
    method: "POST",
    csrf: true,
  });
  const result = data.diagnostics;
  els.operationOutput.textContent = JSON.stringify(result, null, 2);
}

function renderSession(me) {
  els.sessionPanel.innerHTML = `
    <div><strong>${escapeHTML(me.user.username)}</strong></div>
    <div>${me.user.is_admin ? "Администратор" : "Пользователь"}</div>
  `;
}

function renderLoggedOut() {
  els.pageTitle.textContent = "Вход";
  els.pageSubtitle.textContent = "Авторизация в AGP";
  els.loginView.classList.remove("hidden");
  els.portalView.classList.add("hidden");
  els.adminView.classList.add("hidden");
  els.logoutButton.classList.add("hidden");
  els.sessionPanel.innerHTML = `<span class="muted">Нет активной сессии</span>`;
}

async function api(path, options = {}) {
  const init = {
    method: options.method || "GET",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
    },
  };
  if (options.body) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  if (options.csrf) {
    init.headers["X-CSRF-Token"] = state.csrfToken;
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload.error || "";
    } catch {
      detail = await response.text().catch(() => "");
    }
    throw new Error(`HTTP ${response.status}${detail ? `: ${detail}` : ""}`);
  }
  if (response.status === 204) {
    return {};
  }
  return response.json();
}

function splitCSV(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

bootstrap();
