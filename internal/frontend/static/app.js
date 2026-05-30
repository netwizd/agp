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
  adminGroups: [],
  resourceQuery: "",
  resourceCategory: "all",
  editingResourceID: "",
  editingGroupID: "",
  editingUserID: "",
  editingDownloadID: "",
  auditFilters: {},
};

const permissionLabels = {
  "dashboard.read": "Дашборд",
  "users.read": "Пользователи: просмотр",
  "users.manage": "Пользователи: управление",
  "users.superadmin.manage": "Super-admin",
  "groups.read": "Группы: просмотр",
  "groups.manage": "Группы: управление",
  "resources.read": "Ресурсы: просмотр",
  "resources.manage": "Ресурсы: управление",
  "resources.diagnostics": "Диагностика ресурсов",
  "nginx.recommendations.read": "Nginx рекомендации",
  "downloads.read": "Файлы: просмотр",
  "downloads.manage": "Файлы: управление",
  "portal.settings.read": "Портал: просмотр",
  "portal.settings.manage": "Портал: управление",
  "sessions.read": "Сессии: просмотр",
  "sessions.revoke": "Сессии: отзыв",
  "audit.read": "Аудит: просмотр",
  "audit.export": "Аудит: экспорт",
};

const permissionDescriptions = {
  "dashboard.read": "Просмотр счетчиков и краткой сводки в админке.",
  "users.read": "Просмотр списка пользователей и их групп.",
  "users.manage": "Создание, редактирование, блокировка и удаление пользователей.",
  "users.superadmin.manage": "Выдача и отзыв глобального статуса администратора.",
  "groups.read": "Просмотр групп и назначенных им прав.",
  "groups.manage": "Создание, редактирование и удаление групп.",
  "resources.read": "Просмотр ресурсов, групп доступа, CIDR и Nginx-рекомендаций.",
  "resources.manage": "Создание, редактирование и удаление ресурсов портала.",
  "resources.diagnostics": "Запуск диагностики DNS/TCP/HTTP для upstream ресурсов.",
  "nginx.recommendations.read": "Генерация Nginx snippets и полного bundle.",
  "downloads.read": "Просмотр публичных файлов в админке.",
  "downloads.manage": "Загрузка, публикация, скрытие и удаление публичных файлов.",
  "portal.settings.read": "Просмотр настроек оформления портала.",
  "portal.settings.manage": "Изменение логотипа, заголовков, help/support и footer.",
  "sessions.read": "Просмотр активных пользовательских сессий.",
  "sessions.revoke": "Принудительное завершение пользовательских сессий.",
  "audit.read": "Просмотр журнала аудита.",
  "audit.export": "Экспорт журнала аудита в CSV или JSON.",
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
  helpView: document.getElementById("helpView"),
  adminView: document.getElementById("adminView"),
  sessionPanel: document.getElementById("sessionPanel"),
  logoutButton: document.getElementById("logoutButton"),
  showDownloadsButton: document.getElementById("showDownloadsButton"),
  helpButton: document.getElementById("helpButton"),
  identityBadge: document.getElementById("identityBadge"),
  loginForm: document.getElementById("loginForm"),
  loginError: document.getElementById("loginError"),
  resourceGrid: document.getElementById("resourceGrid"),
  resourceSearch: document.getElementById("resourceSearch"),
  categoryFilter: document.getElementById("categoryFilter"),
  backToPortalButton: document.getElementById("backToPortalButton"),
  publicDownloadsLogin: document.getElementById("publicDownloadsLogin"),
  publicDownloadsPortal: document.getElementById("publicDownloadsPortal"),
  downloadsLoginPanel: document.getElementById("downloadsLoginPanel"),
  downloadsPortalPanel: document.getElementById("downloadsPortalPanel"),
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
  resourceGroupSelector: document.getElementById("resourceGroupSelector"),
  nginxBundleButton: document.getElementById("nginxBundleButton"),
  groupForm: document.getElementById("groupForm"),
  userForm: document.getElementById("userForm"),
  userGroupSelector: document.getElementById("userGroupSelector"),
  createUserAdminFlag: document.getElementById("createUserAdminFlag"),
  downloadForm: document.getElementById("downloadForm"),
  downloadSubmitButton: document.getElementById("downloadSubmitButton"),
  downloadUploadStatus: document.getElementById("downloadUploadStatus"),
  downloadUploadProgress: document.getElementById("downloadUploadProgress"),
  downloadUploadText: document.getElementById("downloadUploadText"),
  portalSettingsForm: document.getElementById("portalSettingsForm"),
  refreshAuditButton: document.getElementById("refreshAuditButton"),
  auditFilterForm: document.getElementById("auditFilterForm"),
  resetAuditFiltersButton: document.getElementById("resetAuditFiltersButton"),
  exportAuditCSVButton: document.getElementById("exportAuditCSVButton"),
  exportAuditJSONButton: document.getElementById("exportAuditJSONButton"),
  operationOutput: document.getElementById("operationOutput"),
  copyOperationButton: document.getElementById("copyOperationButton"),
  permissionReference: document.getElementById("permissionReference"),
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

els.showDownloadsButton.addEventListener("click", () => {
  const panel = state.user ? els.downloadsPortalPanel : els.downloadsLoginPanel;
  if (!panel) return;
  panel.open = true;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
});

els.helpButton.addEventListener("click", (event) => {
  event.preventDefault();
  const settings = effectiveSettings();
  if (settings.support_url) {
    window.open(settings.support_url, "_blank", "noopener,noreferrer");
    return;
  }
  setView("help");
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
        category: form.get("category"),
        public_path: form.get("public_path"),
        internal_url: form.get("internal_url"),
        enabled: true,
        group_ids: selectedValues(els.resourceForm, "group_ids"),
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
        group_ids: selectedValues(els.userForm, "group_ids"),
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
  const form = new FormData(els.downloadForm);
  try {
    setDownloadUploadState(true, 0, "Подготовка загрузки");
    await uploadDownload(form, ({ loaded, total, percent }) => {
      if (total > 0) {
        setDownloadUploadState(true, percent, `Загрузка файла: ${percent}% (${formatBytes(loaded)} из ${formatBytes(total)})`);
        return;
      }
      setDownloadUploadState(true, 0, `Загрузка файла: ${formatBytes(loaded)}`);
    });
    els.downloadForm.reset();
    els.downloadForm.elements.enabled.checked = true;
    els.operationOutput.textContent = "Файл добавлен";
    setDownloadUploadState(false, 100, "Загрузка завершена");
    await refreshPublicData();
    await loadAdmin();
  } catch (error) {
    setDownloadUploadState(false, 0, "Ошибка загрузки");
    showOperationError("Не удалось добавить файл", error);
  } finally {
    setDownloadFormBusy(false);
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
els.nginxBundleButton.addEventListener("click", () => showNginxBundle());
els.copyOperationButton.addEventListener("click", () => copyText(els.operationOutput.textContent || ""));

els.auditFilterForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.auditFilters = auditFiltersFromForm();
  await loadAudit();
});

els.resetAuditFiltersButton.addEventListener("click", async () => {
  els.auditFilterForm.reset();
  state.auditFilters = {};
  await loadAudit();
});

els.exportAuditCSVButton.addEventListener("click", () => exportAudit("csv"));
els.exportAuditJSONButton.addEventListener("click", () => exportAudit("json"));

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
    } else if (location.pathname.startsWith("/help")) {
      await setView("help");
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
  syncNavigation();
  if (!state.user) {
    if (view === "accessDenied") {
      renderAccessDenied();
      return;
    }
    if (view === "help") {
      renderHelp();
      return;
    }
    renderLoggedOut();
    return;
  }
  els.loginView.classList.add("hidden");
  els.portalView.classList.toggle("hidden", view !== "portal");
  els.accessDeniedView.classList.toggle("hidden", view !== "accessDenied");
  els.helpView.classList.toggle("hidden", view !== "help");
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

  if (view === "help") {
    renderHelp();
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
  const canExportAudit = can("audit.export");
  els.exportAuditCSVButton.classList.toggle("hidden", !canExportAudit);
  els.exportAuditJSONButton.classList.toggle("hidden", !canExportAudit);
  renderPermissionReference();
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
      const href = publicResourceURL(resource);
      return `
        <a class="resource-item" href="${href}" target="_blank" rel="noopener noreferrer">
          <span class="resource-category">${escapeHTML(resource.Category || "Общее")}</span>
          <strong>${escapeHTML(resource.Name)}</strong>
          <span class="muted">${escapeHTML(resource.Description || resource.InternalURL || resource.PublicHost)}</span>
          <span>${escapeHTML(resource.PublicPath || resource.PublicHost)}</span>
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
    const haystack = [resource.Name, resource.Description, resource.PublicHost, resource.PublicPath, resource.InternalURL, category]
      .join(" ")
      .toLowerCase();
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
  els.helpView.classList.add("hidden");
  els.accessDeniedView.classList.remove("hidden");
  history.replaceState(null, "", "/access-denied");
}

function renderHelp() {
  els.pageTitle.textContent = "Помощь";
  els.pageSubtitle.textContent = "Информация для работы с порталом";
  els.loginView.classList.add("hidden");
  els.portalView.classList.add("hidden");
  els.adminView.classList.add("hidden");
  els.accessDeniedView.classList.add("hidden");
  els.helpView.classList.remove("hidden");
  history.replaceState(null, "", "/help");
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
    els.helpButton.textContent = settings.support_text;
    els.helpButton.classList.remove("hidden");
  } else {
    els.supportLink.classList.add("hidden");
    els.helpButton.textContent = "Помощь";
    els.helpButton.classList.remove("hidden");
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
  attachCopyHandlers(els.publicDownloadsLogin);
  attachCopyHandlers(els.publicDownloadsPortal);
}

function renderDownloadLinks(downloads) {
  if (!downloads.length) {
    return `<div class="muted">Публичные файлы пока не опубликованы.</div>`;
  }
  return downloads
    .map((download) => {
      const size = formatBytes(download.size_bytes || 0);
      const sha = escapeHTML(download.sha256 || "");
      return `
        <div class="download-item">
          <a href="${escapeHTML(download.url)}">
            <strong>${escapeHTML(download.title)}</strong>
            <span class="muted">${escapeHTML(download.description || download.file_name)}</span>
            <span>${escapeHTML(download.file_name)} · ${escapeHTML(size)}</span>
          </a>
          ${download.sha256 ? `<div class="hash-row"><span class="hash-line">sha256: ${sha}</span><button class="secondary compact-button" data-copy="${sha}" type="button">Копировать SHA</button></div>` : ""}
        </div>
      `;
    })
    .join("");
}

async function loadResources() {
  els.resourceForm.classList.toggle("hidden", !can("resources.manage"));
  els.nginxBundleButton.classList.toggle("hidden", !can("nginx.recommendations.read"));
  await ensureGroupLookup();
  if (els.resourceGroupSelector) {
    els.resourceGroupSelector.innerHTML = renderGroupSelector([], "Группы не созданы. Без группы доступ к ресурсу будет запрещен.");
    bindGroupSelectors(els.resourceGroupSelector);
  }
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
          <div class="muted">${escapeHTML(resource.PublicHost)}${escapeHTML(resource.PublicPath || "")} -> ${escapeHTML(resource.InternalURL)}</div>
          <div class="chip-row">${groupChips(resource.GroupIDs || [])}</div>
          <div class="muted">cidrs: ${escapeHTML((resource.AllowCIDRs || []).join(", ") || "any")}</div>
        </div>
        <div class="row-actions">
          ${can("resources.manage") ? `<button class="secondary" data-action="edit-resource" data-id="${escapeHTML(resource.ID)}">Редактировать</button>` : ""}
	          ${can("nginx.recommendations.read") ? `<button class="secondary" data-action="nginx" data-id="${escapeHTML(resource.ID)}">Nginx</button>` : ""}
	          ${can("resources.diagnostics") ? `<button class="secondary" data-action="diag" data-id="${escapeHTML(resource.ID)}">Диагностика</button>` : ""}
	          ${can("resources.diagnostics") ? `<button class="secondary" data-action="diag-history" data-id="${escapeHTML(resource.ID)}">История</button>` : ""}
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
    bindGroupSelectors(form);
    form.addEventListener("submit", (event) => submitResourceEdit(event, form));
  });
}

function renderResourceEditForm(resource) {
  return `
    <form class="inline-edit-form" data-resource-edit data-id="${escapeHTML(resource.ID)}">
      <input name="name" placeholder="Название" value="${escapeHTML(resource.Name)}" required />
      <input name="category" placeholder="Группа в каталоге" value="${escapeHTML(resource.Category || "")}" />
      <input name="public_host" placeholder="public host портала" value="${escapeHTML(resource.PublicHost)}" />
      <input name="public_path" placeholder="/anything-needed" value="${escapeHTML(resource.PublicPath || "")}" required />
      <input name="internal_url" placeholder="http://internal.local" value="${escapeHTML(resource.InternalURL)}" required />
      <input name="description" placeholder="Описание" value="${escapeHTML(resource.Description || "")}" />
      <div class="form-field-full">${renderGroupSelector(resource.GroupIDs || [], "Группы не созданы. Без группы доступ к ресурсу будет запрещен.")}</div>
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
  state.adminGroups = groups;
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
          <div class="muted">permissions: ${escapeHTML(labelPermissions(group.PermissionIDs || []))}</div>
        </div>
        <div class="row-actions">
          ${can("groups.manage") ? `<button class="secondary" data-action="edit-group" data-id="${escapeHTML(group.ID)}">Редактировать</button>` : ""}
          ${can("groups.manage") ? `<button class="danger" data-action="delete-group" data-id="${escapeHTML(group.ID)}">Удалить</button>` : ""}
        </div>
        ${state.editingGroupID === group.ID ? renderGroupEditForm(group) : ""}
      </div>
    `
    )
    .join("");
  els.adminGroups.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleGroupAction(button.dataset.action, button.dataset.id));
  });
  els.adminGroups.querySelectorAll("form[data-group-edit]").forEach((form) => {
    form.addEventListener("submit", (event) => submitGroupEdit(event, form));
  });
}

async function ensureGroupLookup() {
  if (state.adminGroups.length || !can("groups.read")) {
    return;
  }
  try {
    const data = await api("/api/v1/admin/groups");
    state.adminGroups = data.groups || [];
  } catch {
    state.adminGroups = [];
  }
}

function groupChips(groupIDs) {
  if (!groupIDs.length) return `<span class="muted">groups: none</span>`;
  const byID = new Map(state.adminGroups.map((group) => [group.ID, group.Name]));
  return groupIDs
    .map((id) => `<span class="data-chip">${escapeHTML(byID.get(id) || id)}</span>`)
    .join("");
}

function renderGroupSelector(selectedGroupIDs, emptyMessage) {
  if (!state.adminGroups.length) {
    return `<div class="muted">${escapeHTML(emptyMessage || "Группы не созданы.")}</div>`;
  }
  const selected = new Set(selectedGroupIDs || []);
  return `
    <div class="field-label">Доступные группы</div>
    <div class="selector-chips">
      ${state.adminGroups
        .map(
          (group) => `
          <label class="selector-chip ${selected.has(group.ID) ? "selected" : ""}">
            <input name="group_ids" type="checkbox" value="${escapeHTML(group.ID)}" ${selected.has(group.ID) ? "checked" : ""} />
            <span>${escapeHTML(group.Name)}</span>
          </label>
        `
        )
        .join("")}
    </div>
  `;
}

function labelPermissions(permissionIDs) {
  if (!permissionIDs.length) return "none";
  return permissionIDs.map((id) => permissionLabels[id] || id).join(", ");
}

function renderPermissionReference() {
  if (!els.permissionReference) return;
  const visible = state.view === "admin" && state.adminTab === "groups" && can("groups.read");
  els.permissionReference.classList.toggle("hidden", !visible);
  if (!visible) return;
  els.permissionReference.innerHTML = `
    <h3>Permissions</h3>
    <p class="muted">Эти права управляют только административными возможностями. Доступ к самим сервисам задается привязкой ресурса к группе.</p>
    <div class="permission-list">
      ${Object.keys(permissionLabels)
        .map(
          (id) => `
          <div class="permission-item">
            <code>${escapeHTML(id)}</code>
            <strong>${escapeHTML(permissionLabels[id])}</strong>
            <span class="muted">${escapeHTML(permissionDescriptions[id] || "")}</span>
          </div>
        `
        )
        .join("")}
    </div>
  `;
}

function renderGroupEditForm(group) {
  return `
    <form class="inline-edit-form" data-group-edit data-id="${escapeHTML(group.ID)}">
      <input name="name" placeholder="Название группы" value="${escapeHTML(group.Name)}" required />
      <input name="description" placeholder="Описание" value="${escapeHTML(group.Description || "")}" />
      <input name="permission_ids" placeholder="permissions через запятую" value="${escapeHTML((group.PermissionIDs || []).join(", "))}" />
      <div class="form-actions">
        <button type="submit">Сохранить</button>
        <button class="secondary" type="button" data-action="cancel-group-edit" data-id="${escapeHTML(group.ID)}">Отмена</button>
      </div>
    </form>
  `;
}

async function loadUsers() {
  els.userForm.classList.toggle("hidden", !can("users.manage"));
  els.createUserAdminFlag.classList.toggle("hidden", !can("users.superadmin.manage"));
  await ensureGroupLookup();
  if (els.userGroupSelector) {
    els.userGroupSelector.innerHTML = renderGroupSelector([], "Группы не созданы. Пользователя можно создать без групп и назначить их позже.");
    bindGroupSelectors(els.userGroupSelector);
  }
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
          <div class="chip-row">${groupChips(user.GroupIDs || [])}</div>
          <div class="${user.BlockedAt ? "status-bad" : "status-ok"}">${user.BlockedAt ? "blocked" : "active"}</div>
        </div>
        <div class="row-actions">
          ${can("users.manage") ? `<button class="secondary" data-action="edit-user" data-id="${escapeHTML(user.ID)}">Редактировать</button>` : ""}
          ${can("users.manage") ? `<button class="secondary" data-action="block-user" data-id="${escapeHTML(user.ID)}" data-blocked="${user.BlockedAt ? "false" : "true"}">${user.BlockedAt ? "Разблокировать" : "Блокировать"}</button>` : ""}
          ${can("users.manage") ? `<button class="danger" data-action="delete-user" data-id="${escapeHTML(user.ID)}">Удалить</button>` : ""}
        </div>
        ${state.editingUserID === user.ID ? renderUserEditForm(user) : ""}
      </div>
    `
    )
    .join("");
  els.adminUsers.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => handleUserAction(button.dataset.action, button.dataset.id, button.dataset.blocked === "true"));
  });
  els.adminUsers.querySelectorAll("form[data-user-edit]").forEach((form) => {
    bindGroupSelectors(form);
    form.addEventListener("submit", (event) => submitUserEdit(event, form));
  });
}

function renderUserEditForm(user) {
  return `
    <form class="inline-edit-form" data-user-edit data-id="${escapeHTML(user.ID)}">
      <input name="display_name" placeholder="Отображаемое имя" value="${escapeHTML(user.DisplayName || "")}" />
      <div class="form-field-full">${renderGroupSelector(user.GroupIDs || [], "Группы не созданы. Пользователя можно оставить без групп.")}</div>
      <input name="password" type="password" placeholder="Новый пароль, если нужно" />
      ${
        can("users.superadmin.manage")
          ? `<label class="checkbox-line"><input name="is_admin" type="checkbox" ${user.IsAdmin ? "checked" : ""} /> Администратор</label>`
          : ""
      }
      <label class="checkbox-line">
        <input name="blocked" type="checkbox" ${user.BlockedAt ? "checked" : ""} />
        Заблокирован
      </label>
      <div class="form-actions">
        <button type="submit">Сохранить</button>
        <button class="secondary" type="button" data-action="cancel-user-edit" data-id="${escapeHTML(user.ID)}">Отмена</button>
      </div>
    </form>
  `;
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
  const data = await api(`/api/v1/admin/audit?${auditQueryString(50)}`);
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
	          ${event.MetadataJSON ? `<pre class="metadata-json">${escapeHTML(formatJSON(event.MetadataJSON))}</pre>` : ""}
	        </div>
      </div>
    `
    )
    .join("");
}

function auditFiltersFromForm() {
  const form = new FormData(els.auditFilterForm);
  return {
    username: String(form.get("username") || "").trim(),
    type: String(form.get("type") || "").trim(),
    resource_id: String(form.get("resource_id") || "").trim(),
    outcome: String(form.get("outcome") || "").trim(),
    from: String(form.get("from") || "").trim(),
    to: String(form.get("to") || "").trim(),
  };
}

function auditQueryString(limit) {
  const params = new URLSearchParams({ limit: String(limit) });
  Object.entries(state.auditFilters || {}).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  return params.toString();
}

function exportAudit(format) {
  window.open(`/api/v1/admin/audit/export?${auditQueryString(1000)}&format=${encodeURIComponent(format)}`, "_blank", "noopener,noreferrer");
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
  if (action === "diag-history") {
    await showDiagnosticsHistory(id);
    return;
  }
  if (action === "delete-resource") {
    await deleteEntity(`/api/v1/admin/resources/${encodeURIComponent(id)}`, "Ресурс удален");
  }
}

async function handleGroupAction(action, id) {
  if (action === "edit-group") {
    state.editingGroupID = id;
    await loadGroups();
    return;
  }
  if (action === "cancel-group-edit") {
    state.editingGroupID = "";
    await loadGroups();
    return;
  }
  if (action === "delete-group") {
    await deleteEntity(`/api/v1/admin/groups/${encodeURIComponent(id)}`, "Группа удалена");
  }
}

async function submitGroupEdit(event, form) {
  event.preventDefault();
  const id = form.dataset.id;
  const data = new FormData(form);
  try {
    await api(`/api/v1/admin/groups/${encodeURIComponent(id)}`, {
      method: "PATCH",
      csrf: true,
      body: {
        name: data.get("name"),
        description: data.get("description"),
        permission_ids: splitCSV(data.get("permission_ids")),
      },
    });
    state.editingGroupID = "";
    els.operationOutput.textContent = "Группа обновлена";
    await loadGroups();
  } catch (error) {
    showOperationError("Не удалось обновить группу", error);
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
        public_path: data.get("public_path"),
        internal_url: data.get("internal_url"),
        enabled: data.get("enabled") === "on",
        group_ids: selectedValues(form, "group_ids"),
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
	          ${download.SHA256 ? `<div class="hash-row"><span class="muted hash-line">sha256: ${escapeHTML(download.SHA256)}</span><button class="secondary compact-button" data-copy="${escapeHTML(download.SHA256)}" type="button">Копировать SHA</button></div>` : ""}
	          <div class="muted">${escapeHTML(download.Description || "Без описания")}</div>
	          <div class="${download.Enabled ? "status-ok" : "status-bad"}">${download.Enabled ? "published" : "disabled"}</div>
	        </div>
	        <div class="row-actions">
	          <a class="button-link secondary" href="/downloads/${escapeHTML(download.ID)}">Скачать</a>
	          ${can("downloads.manage") ? `<button class="secondary" data-action="edit-download" data-id="${escapeHTML(download.ID)}">Редактировать</button>` : ""}
	          ${
            can("downloads.manage")
              ? `<button class="secondary" data-action="toggle-download" data-id="${escapeHTML(download.ID)}" data-enabled="${download.Enabled ? "false" : "true"}">${download.Enabled ? "Скрыть" : "Опубликовать"}</button>`
              : ""
          }
	          ${can("downloads.manage") ? `<button class="danger" data-action="delete-download" data-id="${escapeHTML(download.ID)}">Удалить</button>` : ""}
	        </div>
	        ${state.editingDownloadID === download.ID ? renderDownloadEditForm(download) : ""}
	      </div>
    `
    )
    .join("");
  els.adminDownloads.querySelectorAll("button").forEach((button) => {
    if (button.dataset.copy) return;
    button.addEventListener("click", () => handleDownloadAction(button.dataset.action, button.dataset.id, button.dataset.enabled === "true"));
  });
  attachCopyHandlers(els.adminDownloads);
  els.adminDownloads.querySelectorAll("form[data-download-edit]").forEach((form) => {
    form.addEventListener("submit", (event) => submitDownloadEdit(event, form));
  });
}

function renderDownloadEditForm(download) {
  return `
    <form class="inline-edit-form" data-download-edit data-id="${escapeHTML(download.ID)}">
      <input name="title" placeholder="Название" value="${escapeHTML(download.Title)}" required />
      <input name="description" placeholder="Описание" value="${escapeHTML(download.Description || "")}" />
      <label class="checkbox-line">
        <input name="enabled" type="checkbox" ${download.Enabled ? "checked" : ""} />
        Опубликован
      </label>
      <div class="form-actions">
        <button type="submit">Сохранить</button>
        <button class="secondary" type="button" data-action="cancel-download-edit" data-id="${escapeHTML(download.ID)}">Отмена</button>
      </div>
    </form>
  `;
}

async function handleDownloadAction(action, id, enabled) {
  if (action === "edit-download") {
    state.editingDownloadID = id;
    await loadDownloads();
    return;
  }
  if (action === "cancel-download-edit") {
    state.editingDownloadID = "";
    await loadDownloads();
    return;
  }
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

async function submitDownloadEdit(event, form) {
  event.preventDefault();
  const id = form.dataset.id;
  const data = new FormData(form);
  try {
    await api(`/api/v1/admin/downloads/${encodeURIComponent(id)}`, {
      method: "PATCH",
      csrf: true,
      body: {
        title: data.get("title"),
        description: data.get("description"),
        enabled: data.get("enabled") === "on",
      },
    });
    state.editingDownloadID = "";
    els.operationOutput.textContent = "Файл обновлен";
    await refreshPublicData();
    await loadDownloads();
  } catch (error) {
    showOperationError("Не удалось обновить файл", error);
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
  if (action === "edit-user") {
    state.editingUserID = id;
    await loadUsers();
    return;
  }
  if (action === "cancel-user-edit") {
    state.editingUserID = "";
    await loadUsers();
    return;
  }
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

async function submitUserEdit(event, form) {
  event.preventDefault();
  const id = form.dataset.id;
  const data = new FormData(form);
  const body = {
    display_name: data.get("display_name"),
    group_ids: selectedValues(form, "group_ids"),
    blocked: data.get("blocked") === "on",
  };
  if (can("users.superadmin.manage")) {
    body.is_admin = data.get("is_admin") === "on";
  }
  if (String(data.get("password") || "").trim() !== "") {
    body.password = data.get("password");
  }
  try {
    await api(`/api/v1/admin/users/${encodeURIComponent(id)}`, {
      method: "PATCH",
      csrf: true,
      body,
    });
    state.editingUserID = "";
    els.operationOutput.textContent = "Пользователь обновлен";
    await loadUsers();
  } catch (error) {
    showOperationError("Не удалось обновить пользователя", error);
  }
}

async function deleteEntity(path, message) {
  if (!window.confirm("Подтвердите удаление. Операция необратима.")) {
    return;
  }
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

async function showNginxBundle() {
  const data = await api("/api/v1/admin/nginx/bundle");
  els.operationOutput.textContent = data.nginx.snippet;
}

function attachCopyHandlers(root) {
  root.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      copyText(button.dataset.copy || "");
    });
  });
}

async function copyText(value) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
}

async function showDiagnostics(id) {
  const data = await api(`/api/v1/admin/resources/${encodeURIComponent(id)}/diagnostics`, {
    method: "POST",
    csrf: true,
  });
  els.operationOutput.textContent = renderDiagnosticsText(data.diagnostics, data.history || []);
}

async function showDiagnosticsHistory(id) {
  const data = await api(`/api/v1/admin/resources/${encodeURIComponent(id)}/diagnostics?limit=20`);
  els.operationOutput.textContent = renderDiagnosticsText(null, data.history || []);
}

function renderDiagnosticsText(current, history) {
  const sections = [];
  if (current) {
    sections.push(`CURRENT\n${JSON.stringify(current, null, 2)}`);
  }
  if (!history.length) {
    sections.push("HISTORY\nИстория диагностики пуста.");
  } else {
    sections.push(
      "HISTORY\n" +
        history
          .map((run) => `${formatDate(run.CreatedAt)} · ${run.Outcome}\n${formatJSON(run.ResultJSON)}`)
          .join("\n\n")
    );
  }
  return sections.join("\n\n");
}

function renderSession(me) {
  els.sessionPanel.innerHTML = `
    <div><strong>${escapeHTML(me.user.username)}</strong></div>
    <div>${canUseAdmin() ? "Администратор" : "Пользователь"}</div>
  `;
  els.identityBadge.textContent = me.user.display_name || me.user.username;
  els.identityBadge.classList.remove("hidden");
  syncNavigation();
}

function renderLoggedOut() {
  els.pageTitle.textContent = "Вход";
  els.pageSubtitle.textContent = "Авторизация в AGP";
  els.loginView.classList.remove("hidden");
  els.portalView.classList.add("hidden");
  els.accessDeniedView.classList.add("hidden");
  els.helpView.classList.add("hidden");
  els.adminView.classList.add("hidden");
  els.logoutButton.classList.add("hidden");
  els.identityBadge.classList.add("hidden");
  els.sessionPanel.innerHTML = `<span class="muted">Нет активной сессии</span>`;
  syncNavigation();
}

function syncNavigation() {
  document.querySelectorAll(".nav-link").forEach((button) => {
    const view = button.dataset.view;
    const visible = state.user && (view !== "admin" || canUseAdmin());
    button.classList.toggle("hidden", !visible);
    button.classList.toggle("active", visible && view === state.view);
  });
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
    throw new Error(await responseErrorMessage(response));
  }
  if (response.status === 204) {
    return {};
  }
  return response.json();
}

function uploadDownload(form, onProgress) {
  if (form.get("enabled") !== "on") {
    form.set("enabled", "false");
  }
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/admin/downloads");
    xhr.withCredentials = true;
    xhr.setRequestHeader("Accept", "application/json");
    xhr.setRequestHeader("X-CSRF-Token", state.csrfToken);
    xhr.upload.addEventListener("progress", (event) => {
      if (!onProgress) return;
      const total = event.lengthComputable ? event.total : 0;
      const percent = total > 0 ? Math.max(1, Math.min(99, Math.round((event.loaded / total) * 100))) : 0;
      onProgress({ loaded: event.loaded, total, percent });
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(xhr.responseText ? JSON.parse(xhr.responseText) : {});
        } catch {
          reject(new Error("HTTP 200: некорректный JSON-ответ сервера"));
        }
        return;
      }
      reject(new Error(responseErrorText(xhr.status, responseDetail(xhr.responseText))));
    });
    xhr.addEventListener("error", () => reject(new Error("Сетевая ошибка при загрузке файла")));
    xhr.addEventListener("abort", () => reject(new Error("Загрузка файла отменена")));
    xhr.send(form);
  });
}

async function responseErrorMessage(response) {
  let detail = "";
  try {
    const payload = await response.json();
    detail = payload.error || "";
  } catch {
    detail = await response.text().catch(() => "");
  }
  return responseErrorText(response.status, detail);
}

function responseErrorText(status, detail) {
  if (status === 413) {
    return "HTTP 413: файл больше лимита Nginx/client_max_body_size или AGP_DOWNLOAD_MAX_BYTES";
  }
  if (detail === "download_extension_denied") {
    return "HTTP 400: расширение файла запрещено политикой AGP_DOWNLOAD_ALLOWED_EXTENSIONS";
  }
  return `HTTP ${status}${detail ? `: ${detail}` : ""}`;
}

function responseDetail(text) {
  if (!text) return "";
  try {
    const payload = JSON.parse(text);
    return payload.error || text;
  } catch {
    return text;
  }
}

function setDownloadUploadState(active, value, text) {
  els.downloadUploadStatus.classList.remove("hidden");
  els.downloadUploadProgress.value = value;
  els.downloadUploadText.textContent = text;
  setDownloadFormBusy(active);
}

function setDownloadFormBusy(busy) {
  Array.from(els.downloadForm.elements).forEach((element) => {
    element.disabled = busy;
  });
  els.downloadSubmitButton.textContent = busy ? "Загрузка..." : "Добавить файл";
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

function selectedValues(form, name) {
  return Array.from(form.querySelectorAll(`input[name="${name}"]:checked`)).map((input) => input.value);
}

function bindGroupSelectors(root) {
  if (!root) return;
  root.querySelectorAll('.selector-chip input[name="group_ids"]').forEach((input) => {
    const chip = input.closest(".selector-chip");
    const sync = () => {
      if (chip) chip.classList.toggle("selected", input.checked);
    };
    sync();
    input.addEventListener("change", sync);
  });
}

function publicResourceURL(resource) {
  const host = String(resource.PublicHost || window.location.host || "").trim();
  const path = String(resource.PublicPath || "").trim();
  const protocol = window.location.protocol === "http:" ? "http:" : "https:";
  return `${protocol}//${escapeHTML(host)}${escapeHTML(path)}`;
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

function formatJSON(value) {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
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
