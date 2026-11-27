package securitystate

import (
	"context"
	"time"

	"github.com/netwizd/agp/internal/authz"
	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/securityjournal"
	"github.com/netwizd/agp/internal/storage"
)

// Portal metadata is not an identity grant. It still requires current session,
// MFA and permissions in the same fenced transaction as the write, including a
// private live proof for directory principals. The embedded base Store cannot
// silently bypass that boundary for downloads or branding settings.
func (s *protectedStore) portalMutation(ctx context.Context, permission string, fn func(storage.IdentityTx, string, time.Time) error) error {
	hash, _ := ctx.Value(actorKey{}).(string)
	return s.c.Current(ctx, func(tx storage.IdentityTx, h securityjournal.Head) error {
		if err := s.c.CheckManagementSession(ctx, tx, h, hash); err != nil {
			return err
		}
		actor, err := managementActor(ctx, tx, h, hash, permission)
		if err != nil {
			return err
		}
		if err = fn(tx, actor.ID, h.RecordedAt.UTC()); err != nil {
			return err
		}
		return s.finalIdentityAuthority(ctx, tx, h, hash, &identityAuthorityWitness{actor: actor})
	})
}

func readPortalDownload(ctx context.Context, tx storage.IdentityTx, id string) (*domain.PublicDownload, error) {
	v := &domain.PublicDownload{}
	err := One(ctx, tx, `SELECT id,title,description,file_name,stored_name,content_type,sha256,size_bytes,enabled,created_at,updated_at FROM public_downloads WHERE id=?`, []any{id}, func(row storage.IdentityRows) error {
		return row.Scan(&v.ID, &v.Title, &v.Description, &v.FileName, &v.StoredName, &v.ContentType, &v.SHA256, &v.SizeBytes, &v.Enabled, &v.CreatedAt, &v.UpdatedAt)
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *protectedStore) CreatePublicDownload(ctx context.Context, in domain.PublicDownloadInput) (out *domain.PublicDownload, err error) {
	err = s.portalMutation(ctx, authz.PermDownloadsManage, func(tx storage.IdentityTx, actor string, now time.Time) error {
		id := ID("dl")
		if _, err := tx.Exec(ctx, `INSERT INTO public_downloads(id,title,description,file_name,stored_name,content_type,sha256,size_bytes,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, in.Title, in.Description, in.FileName, in.StoredName, in.ContentType, in.SHA256, in.SizeBytes, in.Enabled, now, now); err != nil {
			return err
		}
		var err error
		out, err = readPortalDownload(ctx, tx, id)
		if err != nil {
			return err
		}
		return Audit(ctx, tx, "portal.download.created", actor, map[string]any{"downloadId": id})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *protectedStore) UpdatePublicDownload(ctx context.Context, id string, in domain.PublicDownloadUpdate) (out *domain.PublicDownload, err error) {
	err = s.portalMutation(ctx, authz.PermDownloadsManage, func(tx storage.IdentityTx, actor string, now time.Time) error {
		v, err := readPortalDownload(ctx, tx, id)
		if err != nil {
			return err
		}
		if in.Title != nil {
			v.Title = *in.Title
		}
		if in.Description != nil {
			v.Description = *in.Description
		}
		if in.Enabled != nil {
			v.Enabled = *in.Enabled
		}
		v.UpdatedAt = now
		if _, err := tx.Exec(ctx, `UPDATE public_downloads SET title=?,description=?,enabled=?,updated_at=? WHERE id=?`, v.Title, v.Description, v.Enabled, now, id); err != nil {
			return err
		}
		out = v
		return Audit(ctx, tx, "portal.download.updated", actor, map[string]any{"downloadId": id})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *protectedStore) DeletePublicDownload(ctx context.Context, id string) error {
	return s.portalMutation(ctx, authz.PermDownloadsManage, func(tx storage.IdentityTx, actor string, _ time.Time) error {
		n, err := tx.Exec(ctx, `DELETE FROM public_downloads WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n != 1 {
			return storage.ErrNotFound
		}
		return Audit(ctx, tx, "portal.download.deleted", actor, map[string]any{"downloadId": id})
	})
}

func (s *protectedStore) UpdatePortalSettings(ctx context.Context, in domain.PortalSettings) (out *domain.PortalSettings, err error) {
	err = s.portalMutation(ctx, authz.PermPortalSettingsManage, func(tx storage.IdentityTx, actor string, now time.Time) error {
		_, err := tx.Exec(ctx, `INSERT INTO portal_settings(id,brand_name,logo_text,portal_title,portal_subtitle,welcome_title,welcome_body,footer_text,support_text,support_url,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET brand_name=excluded.brand_name,logo_text=excluded.logo_text,portal_title=excluded.portal_title,portal_subtitle=excluded.portal_subtitle,welcome_title=excluded.welcome_title,welcome_body=excluded.welcome_body,footer_text=excluded.footer_text,support_text=excluded.support_text,support_url=excluded.support_url,updated_at=excluded.updated_at`, in.BrandName, in.LogoText, in.PortalTitle, in.PortalSubtitle, in.WelcomeTitle, in.WelcomeBody, in.FooterText, in.SupportText, in.SupportURL, now)
		if err != nil {
			return err
		}
		in.UpdatedAt = now
		out = &in
		return Audit(ctx, tx, "portal.settings.updated", actor, map[string]any{})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
