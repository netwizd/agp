const storage = window.localStorage || {
  getItem: () => "",
  setItem: () => {},
  removeItem: () => {},
};

const state = {
  user: null,
  csrfToken: storage.getItem("agp_csrf_token") || "",
  view: "portal",
  adminTab: "resources",
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
  adminTabs: document.getElementById("adminTabs"),
  adminResources: document.getElementById("adminResources"),
  adminGroups: document.getElementById("adminGroups"),
  adminUsers: document.getElementById("adminUsers"),
  adminSessions: document.getElementById("adminSessions"),
  adminAudit: document.getElementById("adminAudit"),
  resourceForm: document.getElementById("resourceForm"),
  groupForm: document.getElementById("groupForm"),
  userForm: document.getElementById("userForm"),
  refreshAuditButton: document.getElementById("refreshAuditButton"),
  operationOutput: document.getElementById("operationOutput"),
};

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

els.adminTabs.querySelectorAll("button").forEach((button) => {
  button.addEventListener("click", () => setAdminTab(button.dataset.adminTab));
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
    storage.setItem("agp_csrf_token", state.csrfToken);
    await bootstrap();
  } catch {
    els.loginError.textContent = "Ошибка авторизации";
  }
});

els.logoutButton.addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST", csrf: true }).catch(() => {});
  storage.removeItem("agp_csrf_token");
  state.user = null;
  renderLoggedOut();
});

els.resourceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.resourceForm);
  try {
    await api("/api/v1/admin/resources", {
      method: "POST",
      csrf: true,
      body: {
        name: form.get("name"),
        public_host: form.get("public_host"),
        internal_url: form.get("internal_url"),
        enabled: true,
        group_ids: splitCSV(form.get("group_ids")),
        allow_cidrs: splitCSV(form.get("allow_cidrs")),
      },
    });
    els.resourceForm.reset();
    await loadAdmin();
  } catch (error) {
    showOperationError("Не удалось создать ресурс", error);
  }
});

els.groupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.groupForm);
  try {
    await api("/api/v1/admin/groups", {
      method: "POST",
      csrf: true,
      body: {
        name: form.get("name"),
        description: form.get("description"),
      },
    });
    els.groupForm.reset();
    await loadAdmin();
  } catch (error) {
    showOperationError("Не удалось создать группу", error);
  }
});

els.userForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.userForm);
  try {
    await api("/api/v1/admin/users", {
      method: "POST",
      csrf: true,
      body: {
        username: form.get("username"),
        display_name: form.get("display_name"),
        password: form.get("password"),
        is_admin: form.get("is_admin") === "on",
        group_ids: splitCSV(form.get("group_ids")),
      },
    });
    els.userForm.reset();
    await loadAdmin();
  } catch (error) {
    showOperationError("Не удалось создать пользователя", error);
  }
});

els.refreshAuditButton.addEventListener("click", () => loadAudit());

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

async function setAdminTab(tab) {
  state.adminTab = tab;
  els.adminTabs.querySelectorAll("button").forEach((button) => {
    button.classList.toggle("active", button.dataset.adminTab === tab);
  });
  document.querySelectorAll(".admin-tab-panel").forEach((panel) => {
    panel.classList.toggle("hidden", panel.id !== `${tab}Panel`);
  });
  await loadAdmin();
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
  const dashboard = await api("/api/v1/admin/dashboard");
  renderMetrics(dashboard);
  if (state.adminTab === "resources") await loadResources();
  if (state.adminTab === "groups") await loadGroups();
  if (state.adminTab === "users") await loadUsers();
  if (state.adminTab === "sessions") await loadSessions();
  if (state.adminTab === "audit") await loadAudit();
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

async function loadResources() {
  const data = await api("/api/v1/admin/resources");
  renderAdminResources(data.resources || []);
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
          <div class="muted">groups: ${escapeHTML((resource.GroupIDs || []).join(", ") || "none")}</div>
        </div>
        <div class="row-actions">
          <button class="secondary" data-action="nginx" data-id="${escapeHTML(resource.ID)}">Nginx</button>
          <button class="secondary" data-action="diag" data-id="${escapeHTML(resource.ID)}">Диагностика</button>
          <button class="danger" data-action="delete-resource" data-id="${escapeHTML(resource.ID)}">Удалить</button>
        </div>
      </div>
    `
    )
    .join("");
  els.adminResources.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleResourceAction(button.dataset.action, button.dataset.id));
  });
}

async function loadGroups() {
  const data = await api("/api/v1/admin/groups");
  const groups = data.groups || [];
  if (groups.length === 0) {
    els.adminGroups.innerHTML = `<div class="muted">Группы еще не созданы.</div>`;
    return;
  }
  els.adminGroups.innerHTML = groups
    .map(
      (group) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(group.Name)}</strong>
          <div class="muted">${escapeHTML(group.Description || "Без описания")}</div>
          <div class="muted">id: ${escapeHTML(group.ID)}</div>
        </div>
        <div class="row-actions">
          <button class="danger" data-action="delete-group" data-id="${escapeHTML(group.ID)}">Удалить</button>
        </div>
      </div>
    `
    )
    .join("");
  els.adminGroups.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => deleteEntity(`/api/v1/admin/groups/${encodeURIComponent(button.dataset.id)}`, "Группа удалена"));
  });
}

async function loadUsers() {
  const data = await api("/api/v1/admin/users");
  const users = data.users || [];
  if (users.length === 0) {
    els.adminUsers.innerHTML = `<div class="muted">Пользователи еще не созданы.</div>`;
    return;
  }
  els.adminUsers.innerHTML = users
    .map(
      (user) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(user.Username)}</strong>
          <div class="muted">${escapeHTML(user.DisplayName || "Без имени")} · ${user.IsAdmin ? "admin" : "user"}</div>
          <div class="${user.BlockedAt ? "status-bad" : "status-ok"}">${user.BlockedAt ? "blocked" : "active"}</div>
        </div>
        <div class="row-actions">
          <button class="secondary" data-action="block-user" data-id="${escapeHTML(user.ID)}" data-blocked="${user.BlockedAt ? "false" : "true"}">${user.BlockedAt ? "Разблокировать" : "Блокировать"}</button>
          <button class="danger" data-action="delete-user" data-id="${escapeHTML(user.ID)}">Удалить</button>
        </div>
      </div>
    `
    )
    .join("");
  els.adminUsers.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleUserAction(button.dataset.action, button.dataset.id, button.dataset.blocked === "true"));
  });
}

async function loadSessions() {
  const data = await api("/api/v1/admin/sessions");
  const sessions = data.sessions || [];
  if (sessions.length === 0) {
    els.adminSessions.innerHTML = `<div class="muted">Активных сессий нет.</div>`;
    return;
  }
  els.adminSessions.innerHTML = sessions
    .map(
      (session) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(session.Username)}</strong>
          <div class="muted">${escapeHTML(session.IP)} · expires ${formatDate(session.ExpiresAt)}</div>
          <div class="muted">${escapeHTML(session.UserAgent)}</div>
        </div>
        <div class="row-actions">
          <button class="danger" data-id="${escapeHTML(session.ID)}">Отозвать</button>
        </div>
      </div>
    `
    )
    .join("");
  els.adminSessions.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => deleteEntity(`/api/v1/admin/sessions/${encodeURIComponent(button.dataset.id)}`, "Сессия отозвана"));
  });
}

async function loadAudit() {
  const data = await api("/api/v1/admin/audit?limit=50");
  const events = data.events || [];
  if (events.length === 0) {
    els.adminAudit.innerHTML = `<div class="muted">Audit events отсутствуют.</div>`;
    return;
  }
  els.adminAudit.innerHTML = events
    .map(
      (event) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(event.Type)}</strong>
          <div class="muted">${escapeHTML(event.Username || event.SubjectUserID || "system")} · ${escapeHTML(event.Outcome)} · ${formatDate(event.CreatedAt)}</div>
          <div class="muted">${escapeHTML(event.Reason || event.ResourceID || "")}</div>
        </div>
      </div>
    `
    )
    .join("");
}

async function handleResourceAction(action, id) {
  if (action === "nginx") {
    await showNginx(id);
    return;
  }
  if (action === "diag") {
    await showDiagnostics(id);
    return;
  }
  if (action === "delete-resource") {
    await deleteEntity(`/api/v1/admin/resources/${encodeURIComponent(id)}`, "Ресурс удален");
  }
}

async function handleUserAction(action, id, blocked) {
  if (action === "block-user") {
    try {
      await api(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
        method: "PATCH",
        csrf: true,
        body: { blocked },
      });
      els.operationOutput.textContent = blocked ? "Пользователь заблокирован" : "Пользователь разблокирован";
      await loadAdmin();
    } catch (error) {
      showOperationError("Не удалось изменить пользователя", error);
    }
    return;
  }
  if (action === "delete-user") {
    await deleteEntity(`/api/v1/admin/users/${encodeURIComponent(id)}`, "Пользователь удален");
  }
}

async function deleteEntity(path, message) {
  try {
    await api(path, { method: "DELETE", csrf: true });
    els.operationOutput.textContent = message;
    await loadAdmin();
  } catch (error) {
    showOperationError("Операция не выполнена", error);
  }
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
  els.operationOutput.textContent = JSON.stringify(data.diagnostics, null, 2);
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

function showOperationError(prefix, error) {
  els.operationOutput.textContent = `${prefix}: ${error.message}`;
}

function splitCSV(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
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
