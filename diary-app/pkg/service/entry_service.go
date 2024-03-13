package service

import (
    "context"
    // Импортируйте необходимые пакеты
)

// EntryService определяет методы для работы с записями дневника.
type EntryService interface {
    CreateEntry(ctx context.Context, userID int, content string) error
    // Другие методы работы с записями...
}

// entryService реализует EntryService интерфейс.
type entryService struct {
    entryRepo EntryRepository
}

// NewEntryService создает новый экземпляр entryService.
func NewEntryService(entryRepo EntryRepository) EntryService {
    return &entryService{
        entryRepo: entryRepo,
    }
}

// CreateEntry создает новую запись в дневнике для указанного пользователя.
func (s *entryService) CreateEntry(ctx context.Context, userID int, content string) error {
    // Создание новой записи
    newEntry := &Entry{
        UserID:  userID,
        Content: content,
    }

    // Сохранение записи в хранилище
    err := s.entryRepo.CreateEntry(ctx, newEntry)
    if err != nil {
        return err
    }

    return nil
}

// Другие методы работы с записями...


