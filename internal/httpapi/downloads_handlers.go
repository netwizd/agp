package httpapi

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/netwizd/agp/internal/domain"
	"github.com/netwizd/agp/internal/storage"
)

type adminDownloadUpdateRequest struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Enabled     *bool   `json:"enabled"`
}

func (s *Server) publicDownloads(w http.ResponseWriter, r *http.Request) {
	downloads, err := s.store.ListPublicDownloads(r.Context(), false)
	if err != nil {
		s.logger.Error("public downloads list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "downloads_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"downloads": publicDownloads(downloads)})
}

func (s *Server) downloadPublicFile(w http.ResponseWriter, r *http.Request) {
	download, err := s.store.FindPublicDownloadByID(r.Context(), r.PathValue("id"))
	if err != nil || !download.Enabled {
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Error("public download lookup failed", "error", err)
		}
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	path, err := s.downloadPath(download.StoredName)
	if err != nil {
		s.logger.Error("invalid stored download name", "error", err, "download_id", download.ID)
		writeError(w, http.StatusInternalServerError, "download_failed")
		return
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		s.logger.Error("open public download failed", "error", err, "download_id", download.ID)
		writeError(w, http.StatusInternalServerError, "download_failed")
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		s.logger.Error("stat public download failed", "error", err, "download_id", download.ID)
		writeError(w, http.StatusInternalServerError, "download_failed")
		return
	}
	w.Header().Set("Content-Type", download.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": download.FileName}))
	http.ServeContent(w, r, download.FileName, stat.ModTime(), file)
}

func (s *Server) adminListDownloads(w http.ResponseWriter, r *http.Request, _ *domain.SessionContext) {
	downloads, err := s.store.ListPublicDownloads(r.Context(), true)
	if err != nil {
		s.logger.Error("admin downloads list failed", "error", err)
		writeError(w, http.StatusInternalServerError, "downloads_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"downloads": downloads})
}

func (s *Server) adminCreateDownload(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.DownloadMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_multipart")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file_required")
		return
	}
	defer file.Close()

	fileName := safeFileName(header.Filename)
	if fileName == "" {
		writeError(w, http.StatusBadRequest, "invalid_file_name")
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		title = fileName
	}
	description := strings.TrimSpace(r.FormValue("description"))
	enabled := r.FormValue("enabled") != "false"
	contentType := strings.TrimSpace(header.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	storedName := newID("blob") + strings.ToLower(filepath.Ext(fileName))
	size, err := s.persistDownloadFile(r.Context().Done(), storedName, file)
	if err != nil {
		s.logger.Error("persist public download failed", "error", err)
		writeError(w, http.StatusBadRequest, "file_store_failed")
		return
	}
	download, err := s.store.CreatePublicDownload(r.Context(), domain.PublicDownloadInput{
		Title:       title,
		Description: description,
		FileName:    fileName,
		StoredName:  storedName,
		ContentType: contentType,
		SizeBytes:   size,
		Enabled:     enabled,
	})
	if err != nil {
		_ = s.removeDownloadFile(storedName)
		writeStorageError(w, err, "download_create_failed")
		return
	}
	s.audit(r, "admin.download.created", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", download.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"download": download})
}

func (s *Server) adminUpdateDownload(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	var req adminDownloadUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	update := domain.PublicDownloadUpdate{
		Title:       trimOptionalText(req.Title, 160),
		Description: trimOptionalText(req.Description, 1000),
		Enabled:     req.Enabled,
	}
	if update.Title != nil && *update.Title == "" {
		writeError(w, http.StatusBadRequest, "invalid_download")
		return
	}
	download, err := s.store.UpdatePublicDownload(r.Context(), r.PathValue("id"), update)
	if err != nil {
		writeStorageError(w, err, "download_update_failed")
		return
	}
	s.audit(r, "admin.download.updated", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", download.ID)
	writeJSON(w, http.StatusOK, map[string]any{"download": download})
}

func (s *Server) adminDeleteDownload(w http.ResponseWriter, r *http.Request, session *domain.SessionContext) {
	id := r.PathValue("id")
	download, err := s.store.FindPublicDownloadByID(r.Context(), id)
	if err != nil {
		writeStorageError(w, err, "download_get_failed")
		return
	}
	if err := s.store.DeletePublicDownload(r.Context(), id); err != nil {
		writeStorageError(w, err, "download_delete_failed")
		return
	}
	if err := s.removeDownloadFile(download.StoredName); err != nil {
		s.logger.Error("remove public download file failed", "error", err, "download_id", id)
	}
	s.audit(r, "admin.download.deleted", session.User.ID, session.User.Username, "", s.clientIP(r), r.UserAgent(), "success", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) persistDownloadFile(done <-chan struct{}, storedName string, src io.Reader) (int64, error) {
	if err := os.MkdirAll(s.cfg.DownloadsDir, 0o750); err != nil {
		return 0, fmt.Errorf("create downloads dir: %w", err)
	}
	tmp, err := os.CreateTemp(s.cfg.DownloadsDir, ".upload-*")
	if err != nil {
		return 0, fmt.Errorf("create temp download: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	limited := io.LimitReader(src, s.cfg.DownloadMaxBytes+1)
	written, err := copyWithCancel(done, tmp, limited)
	closeErr := tmp.Close()
	if err != nil {
		return 0, err
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close temp download: %w", closeErr)
	}
	if written > s.cfg.DownloadMaxBytes {
		return 0, fmt.Errorf("download exceeds configured limit")
	}
	target, err := s.downloadPath(storedName)
	if err != nil {
		return 0, err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return 0, fmt.Errorf("rename download: %w", err)
	}
	return written, nil
}

func copyWithCancel(done <-chan struct{}, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 64*1024)
	var written int64
	for {
		select {
		case <-done:
			return written, fmt.Errorf("request cancelled")
		default:
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, nil
			}
			return written, er
		}
	}
}

func (s *Server) downloadPath(storedName string) (string, error) {
	if storedName == "" || filepath.Base(storedName) != storedName || strings.Contains(storedName, "\x00") {
		return "", fmt.Errorf("invalid stored name")
	}
	return filepath.Join(s.cfg.DownloadsDir, storedName), nil
}

func (s *Server) removeDownloadFile(storedName string) error {
	path, err := s.downloadPath(storedName)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func publicDownloads(downloads []domain.PublicDownload) []map[string]any {
	result := make([]map[string]any, 0, len(downloads))
	for _, download := range downloads {
		result = append(result, map[string]any{
			"id":           download.ID,
			"title":        download.Title,
			"description":  download.Description,
			"file_name":    download.FileName,
			"content_type": download.ContentType,
			"size_bytes":   download.SizeBytes,
			"url":          "/downloads/" + download.ID,
		})
	}
	return result
}

func safeFileName(name string) string {
	name = filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	name = strings.Map(func(r rune) rune {
		switch r {
		case 0, '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return -1
		default:
			return r
		}
	}, name)
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return name
}
