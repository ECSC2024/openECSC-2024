package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/lestrrat-go/libxml2/parser"
	"github.com/lestrrat-go/libxml2/xpath"
	"os"
	"strings"
)

func getServiceReport(roomRequestModel string) string {
	p := parser.New(parser.XMLParseNoEnt)

	if strings.Contains(
		strings.ToLower(roomRequestModel),
		"system") {
		return "Error: you can't use the S-word!"
	}

	doc, err := p.ParseString(roomRequestModel)
	if err != nil {
		return "Error while parsing: " + err.Error()
	}
	defer doc.Free()

	root, err := doc.DocumentElement()
	if err != nil {
		return "Failed to fetch document element: " + err.Error()
	}

	ctx, err := xpath.NewContext(root)
	if err != nil {
		return "Failed to create xpath context: " + err.Error()
	}
	defer ctx.Free()

	child := xpath.String(ctx.Find("/room/name/text()"))
	flag := os.Getenv("FLAG")

	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	filteredChild := strings.ReplaceAll(child, flag, fmt.Sprintf(flag, hex.EncodeToString(suffix)))

	return "You requested the creation of " + filteredChild
}
