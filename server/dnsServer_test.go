package server_test

import (
	"os/exec"
	"strings"
	"testing"
)

/*
 * TestDNSQuery тестирует обработку DNS запросов сервером с помощью утилиты dig.
 * Перед запуском тестов, нужно поднять DNS сервер на 53 порту
 */
func TestDNSQuery(t *testing.T) {
	// Выполняем DNS запрос на запись типа A (IPv4)
	outputA, err := exec.Command("dig", "@localhost", "A", "example.com").CombinedOutput()
	if err != nil {
		t.Fatalf("Ошибка при выполнении DNS запроса типа A: %v", err)
	}

	// Проверяем ответ
	if !strings.Contains(string(outputA), "ANSWER SECTION:") {
		t.Fatalf("Не получен ответ на DNS запрос типа A")
	}

	// Выполняем DNS запрос на запись типа A (IPv4)
	outputB, err := exec.Command("dig", "@localhost", "A", "joe").CombinedOutput()
	if err != nil {
		t.Fatalf("Ошибка при выполнении DNS запроса типа A: %v", err)
	}

	// Проверяем ответ
	if !strings.Contains(string(outputB), "ANSWER SECTION:") {
		t.Fatalf("Не получен ответ на DNS запрос типа A")
	}

	// Выполняем DNS запрос на запись типа A (IPv4). Данного запроса нет среди локальных записей!
	outputC, err := exec.Command("dig", "@localhost", "A", "google.com").CombinedOutput()
	if err != nil {
		t.Fatalf("Ошибка при выполнении DNS запроса типа A: %v", err)
	}

	// Проверяем ответ
	if !strings.Contains(string(outputC), "ANSWER SECTION:") {
		t.Fatalf("Не получен ответ на DNS запрос типа A")
	}
}
