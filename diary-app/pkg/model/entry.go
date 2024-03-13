package model

// Entry - структура, представляющая запись в дневнике.
type Entry struct {
    ID      int    // Уникальный идентификатор записи
    UserID  int    // Идентификатор пользователя, создавшего запись
    Date    string // Дата создания записи
    Content string // Содержание записи
}

// NewEntry - функция для создания новой записи дневника.
func NewEntry(userID int, date, content string) *Entry {
    return &Entry{
        UserID:  userID,
        Date:    date,
        Content: content,
    }
}

