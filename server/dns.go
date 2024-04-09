package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type DNSRecord struct {
	Name  string
	Type  string
	Value string
}

type DNSFlag struct {
	QR           uint16 // 1 бит
	OpCode       uint16 // 4 бита
	AA           uint16 // 1 бит
	TC           uint16 // 1 бит
	RD           uint16 // 1 бит
	RA           uint16 // 1 бит
	Z            uint16 // 3 бита
	ResponseCode uint16 // 4 бита
}

const (
	QRQuery         = 0 // Запрос
	QRResponse      = 1 // Ответ
	OpCodeQuery     = 0 // Стандартный запрос
	OpCodeIQuery    = 1 // Обратный запрос
	OpCodeStatus    = 2 // Запрос статуса сервера
	ResponseNoError = 0 // Нет ошибки
)

var (
	DNSForwarder    = []string{"8.8.8.8:53"}
	localDNSRecords []DNSRecord
)

func Start(port int, dataBaseFileName string) {
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", "localhost", port))
	if err != nil {
		log.Fatal(err)
	}

	server, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Ошибка при запуске UDP сервера:", err)
		return
	}
	defer server.Close()

	fmt.Printf("DNS сервер работает на порту %d\n", port)

	err = loadDNSRecords(dataBaseFileName)
	if err != nil {
		fmt.Println("Ошибка при загрузке DNS записей:", err)
		return
	}

	isRunning := make(chan struct{}, 1)

	go func(finish <-chan struct{}) {
		for {
			select {
			case <-finish:
				break
			default:
				handleRequest(server)
			}
		}
	}(isRunning)

	fmt.Println("Утилита DNS")
	fmt.Println("1. Добавить DNS запись")
	fmt.Println("2. Выйти")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Выберите опцию: ")
		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			addDNSRecord(dataBaseFileName)
		case "2":
			server.Close()
			isRunning <- struct{}{}
			return
		default:
			fmt.Println("Неверная опция. Пожалуйста, выберите еще раз.")
		}
	}
}

func handleRequest(conn *net.UDPConn) {
	buffer := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Ошибка при чтении из UDP соединения:", err)
		return
	}

	if n < 12 {
		fmt.Println("Некорректный DNS запрос")
		return
	}

	domain := parseDomain(buffer)

	localAnswer := findLocalRecord(domain)
	if localAnswer != "" {
		response := buildResponse(buffer[:n], domain, localAnswer)
		_, err = conn.WriteToUDP(response, addr)
		if err != nil {
			fmt.Println("Ошибка при отправке ответа клиенту:", err)
		}
		return
	}

	// Проксируем запрос на другие DNS серверы
	for _, forwarder := range DNSForwarder {
		// Устанавливаем соединение с проксируемым DNS сервером
		forwarderConn, err := net.Dial("udp", forwarder)
		if err != nil {
			fmt.Println("Ошибка при подключении к DNS прокси:", err)
			continue
		}
		defer forwarderConn.Close()

		_, err = forwarderConn.Write(buffer[:n])
		if err != nil {
			fmt.Println("Ошибка при отправке DNS запроса на проксируемый сервер:", err)
			continue
		}

		responseBuffer := make([]byte, 1024)
		_, err = forwarderConn.Read(responseBuffer)
		if err != nil {
			fmt.Println("Ошибка при чтении ответа от проксируемого сервера:", err)
			continue
		}

		// Отправляем ответ клиенту
		_, err = conn.WriteToUDP(responseBuffer, addr)
		if err != nil {
			fmt.Println("Ошибка при отправке ответа клиенту:", err)
			continue
		}

		// Если мы успешно получили ответ от одного из проксируемых серверов, выходим из цикла
		return
	}
}

func parseDomain(data []byte) string {
	var domain strings.Builder
	start := 12

	for i := start; i < len(data); {
		length := int(data[i])
		if length == 0 {
			break
		}

		if i+length >= len(data) {
			break
		}

		segment := string(data[i+1 : i+1+length])
		domain.WriteString(segment)
		domain.WriteByte('.')

		i += length + 1
	}

	domainString := domain.String()
	if len(domainString) > 0 && domainString[len(domainString)-1] == '.' {
		domainString = domainString[:len(domainString)-1]
	}

	return domainString
}

func encodeDomain(domain string) []byte {
	var encodedDomain []byte

	segments := strings.Split(domain, ".")
	for _, segment := range segments {
		encodedDomain = append(encodedDomain, byte(len(segment)))
		encodedDomain = append(encodedDomain, []byte(segment)...)
	}

	// Terminating zero-length segment
	encodedDomain = append(encodedDomain, 0)

	return encodedDomain
}

func buildResponse(request []byte, domain string, answer string) []byte {
	answerLen := len(answer)
	headerLen := 12
	header := make([]byte, headerLen)
	copy(header[:headerLen], request[:headerLen])

	// Задаем флаги ответа
	dnsFlags := DNSFlag{
		QR:           QRResponse,
		OpCode:       OpCodeQuery,
		ResponseCode: ResponseNoError,
	}
	flags := packFlags(dnsFlags)
	copy(header[2:4], flags[:2])
	binary.BigEndian.PutUint16(header[6:8], uint16(answerLen))

	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, header)

	binary.Write(buffer, binary.BigEndian, encodeDomain(domain))
	binary.Write(buffer, binary.BigEndian, parseTypeAndClass(request[4:6]))

	binary.Write(buffer, binary.BigEndian, encodeDomain(domain))
	binary.Write(buffer, binary.BigEndian, parseTypeAndClass(request[4:6]))

	ttlBuf := make([]byte, 4)
	binary.BigEndian.AppendUint32(ttlBuf, 60)
	binary.Write(buffer, binary.BigEndian, ttlBuf)

	parts := strings.Split(answer, ".")
	binary.Write(buffer, binary.BigEndian, uint16(len(parts)))

	for _, part := range parts {
		if len(part) > 0 {
			data, _ := strconv.Atoi(part)
			buffer.WriteByte(byte(data))
		}
	}

	return buffer.Bytes()
}

func parseTypeAndClass(data []byte) []byte {
	switch binary.BigEndian.Uint16(data) {
	case 0x0001: // Type A
		return []byte{0x00, 0x01, 0x00, 0x01} // Class IN
	case 0x0005: // Type CNAME
		return []byte{0x00, 0x05, 0x00, 0x01} // Class IN
	case 0x001c: // Type AAAA
		return []byte{0x00, 0x1c, 0x00, 0x01} // Class IN
	default:
		return nil // Unknown type and class
	}
}

func packFlags(flags DNSFlag) []byte {
	return []byte{
		byte(flags.QR<<7 | flags.OpCode<<3 | flags.AA<<2 | flags.TC<<1 | flags.RD),
		byte(flags.RA<<7 | flags.Z<<4 | flags.ResponseCode),
	}
}

func findLocalRecord(domain string) string {
	for _, record := range localDNSRecords {
		return record.Value
	}

	return ""
}

func loadDNSRecords(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ";") || len(strings.TrimSpace(line)) == 0 {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		recordType := parts[2]
		value := parts[3]

		localDNSRecords = append(localDNSRecords, DNSRecord{Name: name, Type: recordType, Value: value})
	}

	return scanner.Err()
}

func addDNSRecord(filename string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Введите DNS запись в следующем формате:")
	fmt.Println("<name> <type> <value>")
	fmt.Print("Пример: example.com IN A 192.168.1.1\n")
	fmt.Print("Запись: ")

	record, _ := reader.ReadString('\n')
	record = strings.TrimSpace(record)

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Ошибка при открытии файла:", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(record + "\n"); err != nil {
		fmt.Println("Ошибка при записи в файл:", err)
		return
	}

	fmt.Println("DNS запись успешно добавлена.")
}
