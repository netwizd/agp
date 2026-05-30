const storage = window.localStorage || {
  getItem: () => "",
  setItem: () => {},
  removeItem: () => {},
};

const state = {
  user: null,
  permissions: [],
  csrfToken: storage.getItem("agp_csrf_token") || "",
  view: "portal",
  adminTab: "resources",
  settings: null,
  publicDownloads: [],
  resources: [],
  resourceQuery: "",
  resourceCategory: "all",
  editingResourceID: "",
};

const els = {
  brandMark: document.getElementById("brandMark"),
  brandTitle: document.getElementById("brandTitle"),
  brandSubtitle: document.getElementById("brandSubtitle"),
  pageTitle: document.getElementById("pageTitle"),
  pageSubtitle: document.getElementById("pageSubtitle"),
  loginView: document.getElementById("loginView"),
  portalView: document.getElementById("portalView"),
  accessDeniedView: document.getElementById("accessDeniedView"),
  adminView: document.getElementById("adminView"),
  sessionPanel: document.getElementById("sessionPanel"),
  logoutButton: document.getElementById("logoutButton"),
  loginForm: document.getElementById("loginForm"),
  loginError: document.getElementById("loginError"),
  resourceGrid: document.getElementById("resourceGrid"),
  resourceSearch: document.getElementById("resourceSearch"),
  categoryFilter: document.getElementById("categoryFilter"),
  backToPortalButton: document.getElementById("backToPortalButton"),
  publicDownloadsLogin: document.getElementById("publicDownloadsLogin"),
  publicDownloadsPortal: document.getElementById("publicDownloadsPortal"),
  welcomeTitle: document.getElementById("welcomeTitle"),
  welcomeBody: document.getElementById("welcomeBody"),
  supportLink: document.getElementById("supportLink"),
  portalFooter: document.getElementById("portalFooter"),
  metrics: document.getElementById("metrics"),
  adminTabs: document.getElementById("adminTabs"),
  adminResources: document.getElementById("adminResources"),
  adminGroups: document.getElementById("adminGroups"),
  adminUsers: document.getElementById("adminUsers"),
  adminDownloads: document.getElementById("adminDownloads"),
  adminSessions: document.getElementById("adminSessions"),
  adminAudit: document.getElementById("adminAudit"),
  resourceForm: document.getElementById("resourceForm"),
  groupForm: document.getElementById("groupForm"),
  userForm: document.getElementById("userForm"),
  downloadForm: document.getElementById("downloadForm"),
  portalSettingsForm: document.getElementById("portalSettingsForm"),
  refreshAuditButton: document.getElementById("refreshAuditButton"),
  operationOutput: document.getElementById("operationOutput"),
};

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

els.adminTabs.querySelectorAll("button").forEach((button) => {
  button.addEventListener("click", () => setAdminTab(button.dataset.adminTab));
});

els.resourceSearch.addEventListener("input", () => {
  state.resourceQuery = els.resourceSearch.value.trim().toLowerCase();
  renderResources();
});

els.backToPortalButton.addEventListener("click", () => setView("portal"));

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
        category: form.get("category"),
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
        permission_ids: splitCSV(form.get("permission_ids")),
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

els.downloadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await uploadDownload(new FormData(els.downloadForm));
    els.downloadForm.reset();
    els.downloadForm.elements.enabled.checked = true;
    els.operationOutput.textContent = "Файл добавлен";
    await refreshPublicData();
    await loadAdmin();
  } catch (error) {
    showOperationError("Не удалось добавить файл", error);
  }
});

els.portalSettingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(els.portalSettingsForm);
  try {
    await api("/api/v1/admin/portal-settings", {
      method: "PUT",
      csrf: true,
      body: {
        brand_name: form.get("brand_name"),
        logo_text: form.get("logo_text"),
        portal_title: form.get("portal_title"),
        portal_subtitle: form.get("portal_subtitle"),
        welcome_title: form.get("welcome_title"),
        welcome_body: form.get("welcome_body"),
        support_text: form.get("support_text"),
        support_url: form.get("support_url"),
        footer_text: form.get("footer_text"),
      },
    });
    els.operationOutput.textContent = "Оформление портала сохранено";
    await refreshPublicData();
  } catch (error) {
    showOperationError("Не удалось сохранить оформление", error);
  }
});

els.refreshAuditButton.addEventListener("click", () => loadAudit());

async function bootstrap() {
  await refreshPublicData();
  try {
    const me = await api("/api/v1/me");
    state.user = me.user;
    state.permissions = me.permissions || [];
    renderSession(me);
    els.logoutButton.classList.remove("hidden");
    if (location.pathname.startsWith("/access-denied")) {
      await setView("accessDenied");
    } else if (location.pathname.startsWith("/admin") && canUseAdmin()) {
      await setView("admin");
    } else {
      await setView("portal");
    }
  } catch {
    if (location.pathname.startsWith("/access-denied")) {
      renderAccessDenied();
      return;
    }
    renderLoggedOut();
  }
}

async function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  if (!state.user) {
    if (view === "accessDenied") {
      renderAccessDenied();
      return;
    }
    renderLoggedOut();
    return;
  }
  els.loginView.classList.add("hidden");
  els.portalView.classList.toggle("hidden", view !== "portal");
  els.accessDeniedView.classList.toggle("hidden", view !== "accessDenied");
  els.adminView.classList.toggle("hidden", view !== "admin");

  if (view === "accessDenied") {
    renderAccessDenied();
    return;
  }

  if (view === "admin") {
    els.pageTitle.textContent = "Админка";
    els.pageSubtitle.textContent = "Пользователи, ресурсы, аудит и Nginx";
    history.replaceState(null, "", "/admin");
    syncAdminTabs();
    if (!canOpenAdminTab(state.adminTab)) {
      state.adminTab = firstAvailableAdminTab();
    }
    await loadAdmin();
    return;
  }

  applyPortalTitle();
  history.replaceState(null, "", "/");
  await loadPortal();
}

async function setAdminTab(tab) {
  if (!canOpenAdminTab(tab)) {
    els.operationOutput.textContent = "Нет доступа к выбранному разделу";
    return;
  }
  state.adminTab = tab;
  syncAdminTabs();
  await loadAdmin();
}

function syncAdminTabs() {
  els.adminTabs.querySelectorAll("button").forEach((button) => {
    const visible = canOpenAdminTab(button.dataset.adminTab);
    button.classList.toggle("hidden", !visible);
    button.classList.toggle("active", button.dataset.adminTab === state.adminTab);
  });
  document.querySelectorAll(".admin-tab-panel").forEach((panel) => {
    panel.classList.toggle("hidden", panel.id !== `${state.adminTab}Panel`);
  });
}

async function loadPortal() {
  renderPublicDownloads();
  const data = await api("/api/v1/resources");
  state.resources = data.resources || [];
  state.resourceQuery = "";
  state.resourceCategory = "all";
  els.resourceSearch.value = "";
  renderCategoryFilter();
  renderResources();
}

function renderResources() {
  const resources = filteredResources();
  if (state.resources.length === 0) {
    els.resourceGrid.innerHTML = `<div class="muted">Нет доступных ресурсов.</div>`;
    return;
  }
  if (resources.length === 0) {
    els.resourceGrid.innerHTML = `<div class="muted">По текущему фильтру ничего не найдено.</div>`;
    return;
  }
  els.resourceGrid.innerHTML = resources
    .map((resource) => {
      const href = `https://${escapeHTML(resource.PublicHost)}`;
      return `
        <a class="resource-item" href="${href}" target="_blank" rel="noopener noreferrer">
          <span class="resource-category">${escapeHTML(resource.Category || "Общее")}</span>
          <strong>${escapeHTML(resource.Name)}</strong>
          <span class="muted">${escapeHTML(resource.Description || resource.PublicHost)}</span>
          <span>${escapeHTML(resource.PublicHost)}</span>
        </a>
      `;
    })
    .join("");
}

function filteredResources() {
  return state.resources.filter((resource) => {
    const category = resource.Category || "Общее";
    if (state.resourceCategory !== "all" && category !== state.resourceCategory) {
      return false;
    }
    if (!state.resourceQuery) {
      return true;
    }
    const haystack = [resource.Name, resource.Description, resource.PublicHost, category].join(" ").toLowerCase();
    return haystack.includes(state.resourceQuery);
  });
}

function renderCategoryFilter() {
  const categories = Array.from(new Set(state.resources.map((resource) => resource.Category || "Общее"))).sort((a, b) =>
    a.localeCompare(b)
  );
  const buttons = [
    `<button class="chip ${state.resourceCategory === "all" ? "active" : ""}" data-category="all">Все</button>`,
    ...categories.map(
      (category) =>
        `<button class="chip ${state.resourceCategory === category ? "active" : ""}" data-category="${escapeHTML(category)}">${escapeHTML(category)}</button>`
    ),
  ];
  els.categoryFilter.innerHTML = buttons.join("");
  els.categoryFilter.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      state.resourceCategory = button.dataset.category || "all";
      renderCategoryFilter();
      renderResources();
    });
  });
}

function renderAccessDenied() {
  els.pageTitle.textContent = "Доступ запрещен";
  els.pageSubtitle.textContent = "Ресурс не найден или не разрешен для вашей учетной записи";
  els.loginView.classList.add("hidden");
  els.portalView.classList.add("hidden");
  els.adminView.classList.add("hidden");
  els.accessDeniedView.classList.remove("hidden");
  history.replaceState(null, "", "/access-denied");
}

async function loadAdmin() {
  if (!canUseAdmin()) {
    els.operationOutput.textContent = "Нет административного доступа";
    return;
  }
  if (can("dashboard.read")) {
    const dashboard = await api("/api/v1/admin/dashboard");
    renderMetrics(dashboard);
  } else {
    els.metrics.innerHTML = "";
  }
  if (state.adminTab === "resources") await loadResources();
  if (state.adminTab === "downloads") await loadDownloads();
  if (state.adminTab === "settings") await loadPortalSettings();
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
    ${metric("Файлы", stats.PublicDownloadsCount)}
    ${metric("Audit events", stats.AuditEventsCount)}
  `;
}

function metric(label, value) {
  return `<div class="metric"><strong>${Number(value || 0)}</strong><span class="muted">${label}</span></div>`;
}

async function refreshPublicData() {
  await Promise.all([loadPublicSettings(), loadPublicDownloads()]);
  applyPortalChrome();
  renderPublicDownloads();
}

async function loadPublicSettings() {
  try {
    const data = await api("/api/v1/public/settings");
    state.settings = data.settings || null;
  } catch {
    state.settings = null;
  }
}

async function loadPublicDownloads() {
  try {
    const data = await api("/api/v1/public/downloads");
    state.publicDownloads = data.downloads || [];
  } catch {
    state.publicDownloads = [];
  }
}

function applyPortalChrome() {
  const settings = effectiveSettings();
  els.brandMark.textContent = settings.logo_text;
  els.brandTitle.textContent = settings.brand_name;
  els.brandSubtitle.textContent = settings.portal_subtitle || "Auth Gateway Portal";
  document.title = settings.brand_name;
  els.welcomeTitle.textContent = settings.welcome_title;
  els.welcomeBody.textContent = settings.welcome_body;
  els.portalFooter.textContent = settings.footer_text || "";
  els.portalFooter.classList.toggle("hidden", !settings.footer_text);
  if (settings.support_url && settings.support_text) {
    els.supportLink.textContent = settings.support_text;
    els.supportLink.href = settings.support_url;
    els.supportLink.classList.remove("hidden");
  } else {
    els.supportLink.classList.add("hidden");
  }
  if (state.view === "portal" && state.user) {
    applyPortalTitle();
  }
}

function applyPortalTitle() {
  const settings = effectiveSettings();
  els.pageTitle.textContent = settings.portal_title;
  els.pageSubtitle.textContent = settings.portal_subtitle;
}

function effectiveSettings() {
  return {
    brand_name: state.settings?.brand_name || "AGP",
    logo_text: state.settings?.logo_text || "A",
    portal_title: state.settings?.portal_title || "Портал",
    portal_subtitle: state.settings?.portal_subtitle || "Доступные внутренние ресурсы",
    welcome_title: state.settings?.welcome_title || "Добро пожаловать",
    welcome_body: state.settings?.welcome_body || "Выберите доступный сервис или скачайте вспомогательные материалы.",
    footer_text: state.settings?.footer_text || "",
    support_text: state.settings?.support_text || "",
    support_url: state.settings?.support_url || "",
  };
}

function renderPublicDownloads() {
  const html = renderDownloadLinks(state.publicDownloads);
  els.publicDownloadsLogin.innerHTML = html;
  els.publicDownloadsPortal.innerHTML = html;
}

function renderDownloadLinks(downloads) {
  if (!downloads.length) {
    return `<div class="muted">Публичные файлы пока не опубликованы.</div>`;
  }
  return downloads
    .map((download) => {
      const size = formatBytes(download.size_bytes || 0);
      return `
        <a class="download-item" href="${escapeHTML(download.url)}">
          <strong>${escapeHTML(download.title)}</strong>
          <span class="muted">${escapeHTML(download.description || download.file_name)}</span>
          <span>${escapeHTML(download.file_name)} · ${escapeHTML(size)}</span>
        </a>
      `;
    })
    .join("");
}

async function loadResources() {
  els.resourceForm.classList.toggle("hidden", !can("resources.manage"));
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
          <div class="muted">category: ${escapeHTML(resource.Category || "Общее")}</div>
          <div class="muted">${escapeHTML(resource.PublicHost)} -> ${escapeHTML(resource.InternalURL)}</div>
          <div class="muted">groups: ${escapeHTML((resource.GroupIDs || []).join(", ") || "none")}</div>
          <div class="muted">cidrs: ${escapeHTML((resource.AllowCIDRs || []).join(", ") || "any")}</div>
        </div>
        <div class="row-actions">
          ${can("resources.manage") ? `<button class="secondary" data-action="edit-resource" data-id="${escapeHTML(resource.ID)}">Редактировать</button>` : ""}
          ${can("nginx.recommendations.read") ? `<button class="secondary" data-action="nginx" data-id="${escapeHTML(resource.ID)}">Nginx</button>` : ""}
          ${can("resources.diagnostics") ? `<button class="secondary" data-action="diag" data-id="${escapeHTML(resource.ID)}">Диагностика</button>` : ""}
          ${can("resources.manage") ? `<button class="danger" data-action="delete-resource" data-id="${escapeHTML(resource.ID)}">Удалить</button>` : ""}
        </div>
        ${state.editingResourceID === resource.ID ? renderResourceEditForm(resource) : ""}
      </div>
    `
    )
    .join("");
  els.adminResources.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleResourceAction(button.dataset.action, button.dataset.id));
  });
  els.adminResources.querySelectorAll("form[data-resource-edit]").forEach((form) => {
    form.addEventListener("submit", (event) => submitResourceEdit(event, form));
  });
}

function renderResourceEditForm(resource) {
  return `
    <form class="inline-edit-form" data-resource-edit data-id="${escapeHTML(resource.ID)}">
      <input name="name" placeholder="Название" value="${escapeHTML(resource.Name)}" required />
      <input name="category" placeholder="Группа в каталоге" value="${escapeHTML(resource.Category || "")}" />
      <input name="public_host" placeholder="public host" value="${escapeHTML(resource.PublicHost)}" required />
      <input name="internal_url" placeholder="http://internal.local" value="${escapeHTML(resource.InternalURL)}" required />
      <input name="description" placeholder="Описание" value="${escapeHTML(resource.Description || "")}" />
      <input name="group_ids" placeholder="group ids через запятую" value="${escapeHTML((resource.GroupIDs || []).join(", "))}" />
      <input name="allow_cidrs" placeholder="CIDR через запятую" value="${escapeHTML((resource.AllowCIDRs || []).join(", "))}" />
      <label class="checkbox-line">
        <input name="enabled" type="checkbox" ${resource.Enabled ? "checked" : ""} />
        Включен
      </label>
      <div class="form-actions">
        <button type="submit">Сохранить</button>
        <button class="secondary" type="button" data-action="cancel-resource-edit" data-id="${escapeHTML(resource.ID)}">Отмена</button>
      </div>
    </form>
  `;
}

async function loadGroups() {
  els.groupForm.classList.toggle("hidden", !can("groups.manage"));
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
          <div class="muted">permissions: ${escapeHTML((group.PermissionIDs || []).join(", ") || "none")}</div>
        </div>
        <div class="row-actions">
          ${can("groups.manage") ? `<button class="danger" data-action="delete-group" data-id="${escapeHTML(group.ID)}">Удалить</button>` : ""}
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
  els.userForm.classList.toggle("hidden", !can("users.manage"));
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
          ${can("users.manage") ? `<button class="secondary" data-action="block-user" data-id="${escapeHTML(user.ID)}" data-blocked="${user.BlockedAt ? "false" : "true"}">${user.BlockedAt ? "Разблокировать" : "Блокировать"}</button>` : ""}
          ${can("users.manage") ? `<button class="danger" data-action="delete-user" data-id="${escapeHTML(user.ID)}">Удалить</button>` : ""}
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
          ${can("sessions.revoke") ? `<button class="danger" data-id="${escapeHTML(session.ID)}">Отозвать</button>` : ""}
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
  if (action === "edit-resource") {
    state.editingResourceID = id;
    await loadResources();
    return;
  }
  if (action === "cancel-resource-edit") {
    state.editingResourceID = "";
    await loadResources();
    return;
  }
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

async function submitResourceEdit(event, form) {
  event.preventDefault();
  const id = form.dataset.id;
  const data = new FormData(form);
  try {
    await api(`/api/v1/admin/resources/${encodeURIComponent(id)}`, {
      method: "PATCH",
      csrf: true,
      body: {
        name: data.get("name"),
        category: data.get("category"),
        description: data.get("description"),
        public_host: data.get("public_host"),
        internal_url: data.get("internal_url"),
        enabled: data.get("enabled") === "on",
        group_ids: splitCSV(data.get("group_ids")),
        allow_cidrs: splitCSV(data.get("allow_cidrs")),
      },
    });
    state.editingResourceID = "";
    els.operationOutput.textContent = "Ресурс обновлен";
    await loadResources();
    if (state.view === "portal") {
      await loadPortal();
    }
  } catch (error) {
    showOperationError("Не удалось обновить ресурс", error);
  }
}

async function loadDownloads() {
  els.downloadForm.classList.toggle("hidden", !can("downloads.manage"));
  const data = await api("/api/v1/admin/downloads");
  renderAdminDownloads(data.downloads || []);
}

function renderAdminDownloads(downloads) {
  if (downloads.length === 0) {
    els.adminDownloads.innerHTML = `<div class="muted">Файлы еще не добавлены.</div>`;
    return;
  }
  els.adminDownloads.innerHTML = downloads
    .map(
      (download) => `
      <div class="table-row">
        <div>
          <strong>${escapeHTML(download.Title)}</strong>
          <div class="muted">${escapeHTML(download.FileName)} · ${escapeHTML(formatBytes(download.SizeBytes || 0))}</div>
          <div class="muted">${escapeHTML(download.Description || "Без описания")}</div>
          <div class="${download.Enabled ? "status-ok" : "status-bad"}">${download.Enabled ? "published" : "disabled"}</div>
        </div>
        <div class="row-actions">
          <a class="button-link secondary" href="/downloads/${escapeHTML(download.ID)}">Скачать</a>
          ${
            can("downloads.manage")
              ? `<button class="secondary" data-action="toggle-download" data-id="${escapeHTML(download.ID)}" data-enabled="${download.Enabled ? "false" : "true"}">${download.Enabled ? "Скрыть" : "Опубликовать"}</button>`
              : ""
          }
          ${can("downloads.manage") ? `<button class="danger" data-action="delete-download" data-id="${escapeHTML(download.ID)}">Удалить</button>` : ""}
        </div>
      </div>
    `
    )
    .join("");
  els.adminDownloads.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleDownloadAction(button.dataset.action, button.dataset.id, button.dataset.enabled === "true"));
  });
}

async function handleDownloadAction(action, id, enabled) {
  if (action === "toggle-download") {
    try {
      await api(`/api/v1/admin/downloads/${encodeURIComponent(id)}`, {
        method: "PATCH",
        csrf: true,
        body: { enabled },
      });
      els.operationOutput.textContent = enabled ? "Файл опубликован" : "Файл скрыт";
      await refreshPublicData();
      await loadAdmin();
    } catch (error) {
      showOperationError("Не удалось изменить файл", error);
    }
    return;
  }
  if (action === "delete-download") {
    await deleteEntity(`/api/v1/admin/downloads/${encodeURIComponent(id)}`, "Файл удален");
    await refreshPublicData();
  }
}

async function loadPortalSettings() {
  els.portalSettingsForm.classList.toggle("hidden", !can("portal.settings.manage"));
  const data = await api("/api/v1/admin/portal-settings");
  fillPortalSettingsForm(data.settings || {});
}

function fillPortalSettingsForm(settings) {
  els.portalSettingsForm.elements.brand_name.value = settings.BrandName || "";
  els.portalSettingsForm.elements.logo_text.value = settings.LogoText || "";
  els.portalSettingsForm.elements.portal_title.value = settings.PortalTitle || "";
  els.portalSettingsForm.elements.portal_subtitle.value = settings.PortalSubtitle || "";
  els.portalSettingsForm.elements.welcome_title.value = settings.WelcomeTitle || "";
  els.portalSettingsForm.elements.welcome_body.value = settings.WelcomeBody || "";
  els.portalSettingsForm.elements.support_text.value = settings.SupportText || "";
  els.portalSettingsForm.elements.support_url.value = settings.SupportURL || "";
  els.portalSettingsForm.elements.footer_text.value = settings.FooterText || "";
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
    <div>${canUseAdmin() ? "Администратор" : "Пользователь"}</div>
  `;
}

function renderLoggedOut() {
  els.pageTitle.textContent = "Вход";
  els.pageSubtitle.textContent = "Авторизация в AGP";
  els.loginView.classList.remove("hidden");
  els.portalView.classList.add("hidden");
  els.accessDeniedView.classList.add("hidden");
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

async function uploadDownload(form) {
  const init = {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "X-CSRF-Token": state.csrfToken,
    },
    body: form,
  };
  if (form.get("enabled") !== "on") {
    form.set("enabled", "false");
  }
  const response = await fetch("/api/v1/admin/downloads", init);
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

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function canUseAdmin() {
  return Boolean(state.user?.is_admin || state.permissions?.length);
}

function can(permission) {
  if (state.user?.is_admin || state.permissions?.includes(permission)) {
    return true;
  }
  if (permission.endsWith(".read")) {
    return state.permissions?.includes(`${permission.slice(0, -".read".length)}.manage`);
  }
  return false;
}

function canOpenAdminTab(tab) {
  const permissions = {
    resources: ["resources.read", "resources.manage"],
    downloads: ["downloads.read", "downloads.manage"],
    settings: ["portal.settings.read", "portal.settings.manage"],
    groups: ["groups.read", "groups.manage"],
    users: ["users.read", "users.manage"],
    sessions: ["sessions.read", "sessions.revoke"],
    audit: ["audit.read"],
  };
  return (permissions[tab] || []).some((permission) => can(permission));
}

function firstAvailableAdminTab() {
  return ["resources", "downloads", "settings", "groups", "users", "sessions", "audit"].find((tab) => canOpenAdminTab(tab)) || "resources";
}

bootstrap();
