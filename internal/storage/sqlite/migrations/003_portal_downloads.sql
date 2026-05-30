CREATE TABLE IF NOT EXISTS public_downloads (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    file_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_public_downloads_enabled ON public_downloads(enabled);

CREATE TABLE IF NOT EXISTS portal_settings (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    brand_name TEXT NOT NULL DEFAULT 'AGP',
    logo_text TEXT NOT NULL DEFAULT 'A',
    portal_title TEXT NOT NULL DEFAULT 'Корпоративный портал',
    portal_subtitle TEXT NOT NULL DEFAULT 'Доступные внутренние ресурсы и полезные файлы',
    welcome_title TEXT NOT NULL DEFAULT 'Добро пожаловать',
    welcome_body TEXT NOT NULL DEFAULT 'Выберите доступный сервис или скачайте вспомогательные материалы.',
    footer_text TEXT NOT NULL DEFAULT '',
    support_text TEXT NOT NULL DEFAULT '',
    support_url TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO portal_settings(id) VALUES (1);

INSERT OR IGNORE INTO permissions(id, description) VALUES
    ('downloads.read', 'Read public download metadata in admin'),
    ('downloads.manage', 'Manage public downloads'),
    ('portal.settings.read', 'Read portal settings in admin'),
    ('portal.settings.manage', 'Manage portal settings');
