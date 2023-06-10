package captain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHMAC(t *testing.T) {
	secret := "superSecret"
	secret2 := "superSecret2"
	p1 := Payload{
		Host: "192.168.2.3",
		Task: Task{
			BootDevice: &BootDevice{
				Device:     "pxe",
				Persistent: false,
				EFIBoot:    false,
			},
		},
	}
	pj1, err := json.Marshal(p1)
	if err != nil {
		t.Fatal(err)
	}
	tm1 := "06082023-10:50:45"
	data1 := fmt.Sprintf("%s\n%s", pj1, tm1)

	one := HMAC{
		Hashes: NewSHA256(secret, secret2),
	}

	p2 := Payload{
		Host: "192.168.2.3",
		Task: Task{
			BootDevice: &BootDevice{
				Device:     "pxe",
				Persistent: false,
				EFIBoot:    true,
			},
		},
	}
	pj2, err := json.Marshal(p2)
	if err != nil {
		t.Fatal(err)
	}
	tm2 := "06082023-10:50:45"
	data2 := fmt.Sprintf("%s\n%s", pj2, tm2)
	t.Log(data2)
	second := HMAC{
		Hashes: NewSHA256(secret),
	}

	shas1, err := second.Sign(data1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(shas1)

	shas2, err := one.Sign(data1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(shas2)
	t.Logf("verify: %v", Equal(shas1[SHA256], shas2[SHA256]))

	t.Fail()
}

func configRequest(t *testing.T) *http.Request {
	t.Helper()
	p := Payload{
		Host: "192.168.2.3",
		Task: Task{
			/*BootDevice: &BootDevice{
				Device:     "pxe",
				Persistent: false,
				EFIBoot:    false,
			},*/
			//Power: "on",
			VirtualMedia: &VirtualMedia{
				Kind:     "cdrom",
				MediaURL: "http://netboot.xyz.iso",
			},
		},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewReader(data)
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://192.168.2.50:9000/webhook", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// RFC3339 2006-01-02T15:04:05Z07:00
	req.Header.Add("X-Rufio-Timestamp", time.Now().Format(time.RFC3339))
	req.Header.Add("User-Agent", "rufio/0.0.1")

	return req
}

func TestAddSignature(t *testing.T) {
	// configure HTTP request
	req := configRequest(t)

	// configure HMAC
	// Add signature payload header
	s := Signature{
		Header:         "X-Rufio-Signature",
		PayloadHeaders: []string{"X-Rufio-Timestamp", "User-Agent"},
		HMAC: HMAC{
			Hashes: MergeHashes(NewSHA256("superSecret1", "superSecret2"), NewSHA512("superSecret2")),
		},
	}
	if err := s.AddSignature(req); err != nil {
		t.Fatal(err)
	}

	// Make HTTP request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	// print response body
	t.Logf("statusCode: %v, body: %q", resp.StatusCode, string(respBody))
	t.Fail()
}
