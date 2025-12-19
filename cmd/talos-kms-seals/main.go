package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
	"github.com/siderolabs/go-blockdevice/v2/encryption/luks"
	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type KMSToken struct {
	SealedData []byte `json:"sealedData"`
}

const TokenTypeKMS = "sideroKMS"

// TODO get this from Talos. It's not important for my KMS atm
var uuid = "75717bc6-8bec-42da-ab62-402a27ac6dd2"

const existingKeySlot = 0

func seal(ctx context.Context, cli kms.KMSServiceClient, luksProv *luks.LUKS, device string, slot uint) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalln("failed to generate key")
	}

	resp, err := cli.Seal(ctx, &kms.Request{NodeUuid: uuid, Data: key})
	if err != nil {
		log.Fatalln("failed to unseal", err)
	}

	token := &luks.Token[*KMSToken]{
		Type: TokenTypeKMS,
		UserData: &KMSToken{
			SealedData: resp.Data,
		},
	}

	if err := luksProv.SetToken(ctx, device, int(slot), token); err != nil {
		log.Fatalln("failed to set token", err)
	}

	luksKey := encryption.NewKey(int(slot), []byte(base64.StdEncoding.EncodeToString(key)))

	existingKey, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln("failed to read input", err)
	}

	existingLuksKey := encryption.NewKey(existingKeySlot, []byte(strings.TrimSpace(string(existingKey))))
	if err := luksProv.AddKey(ctx, device, existingLuksKey, luksKey); err != nil {
		log.Fatalln("failed to add key", err)
	}

	log.Println("device token set, key added to slot", slot)
}

func unsealStdin(ctx context.Context, cli kms.KMSServiceClient) {
	sealed, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln("failed to read input", err)
	}

	resp, err := cli.Unseal(ctx, &kms.Request{NodeUuid: uuid, Data: sealed})
	if err != nil {
		log.Fatalln("failed to unseal", err)
	}

	fmt.Printf("%s", resp.Data)
}

func unsealDevice(ctx context.Context, cli kms.KMSServiceClient, luksProv *luks.LUKS, device string, slot uint) {
	token := &luks.Token[*KMSToken]{}

	if err := luksProv.ReadToken(ctx, device, int(slot), token); err != nil {
		log.Fatalln("failed to read token", err)
	}

	resp, err := cli.Unseal(ctx, &kms.Request{NodeUuid: uuid, Data: token.UserData.SealedData})
	if err != nil {
		log.Fatalln("failed to unseal", err)
	}

	fmt.Printf("%s", resp.Data)
}

func open(ctx context.Context, cli kms.KMSServiceClient, luksProv *luks.LUKS, device string, slot uint, mappedName string) {
	token := &luks.Token[*KMSToken]{}

	if err := luksProv.ReadToken(ctx, device, int(slot), token); err != nil {
		log.Fatalln("failed to read token", err)
	}

	resp, err := cli.Unseal(ctx, &kms.Request{NodeUuid: uuid, Data: token.UserData.SealedData})
	if err != nil {
		log.Fatalln("failed to unseal", err)
	}

	key := encryption.NewKey(int(slot), []byte(base64.StdEncoding.EncodeToString(resp.Data)))

	if opened, _, err := luksProv.IsOpen(ctx, device, mappedName); err != nil {
		log.Fatalln("failed to check status", err)
	} else if opened {
		log.Println("volume already opened")
		return
	}

	path, err := luksProv.Open(ctx, device, mappedName, key)
	if err != nil {
		log.Fatalln("failed to open volume", err)
	}

	log.Println("device unlocked at", path)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var kmsFlags struct {
		device     string
		endpoint   string
		slot       uint
		mappedName string
		onlyOnNode string
	}

	flag.StringVar(&kmsFlags.endpoint, "endpoint", ":4050", "gRPC API endpoint for the KMS")
	flag.StringVar(&kmsFlags.device, "device", "", "device to work on")
	slotRaw := flag.Int("slot", -1, "slot for KMS token/key")
	flag.StringVar(&kmsFlags.mappedName, "mapped-name", "", "name of the device under /dev/mapper")
	flag.StringVar(&kmsFlags.onlyOnNode, "only-on-node", "", "if NODE_NAME is not equal to this value, exit immediately")
	flag.Parse()

	if *slotRaw < 0 {
		log.Fatalln("slot > 0 is required")
	}
	kmsFlags.slot = uint(*slotRaw)

	if os.Getenv("NODE_NAME") != kmsFlags.onlyOnNode {
		log.Printf("Environment variable NODE_NAME %q does not equal %q, exiting\n", os.Getenv("NODE_NAME"), kmsFlags.onlyOnNode)
		os.Exit(0)
	}

	if flag.NArg() != 1 {
		log.Fatalf("usage: %s <open|seal|unseal-device|unseal-bytes> [flags]\n", os.Args[0])
	}

	if kmsFlags.endpoint == "" {
		log.Fatalln("endpoint is required")
	}

	endpoint, err := url.Parse(kmsFlags.endpoint)
	if err != nil {
		log.Fatalln("failed to parse KMS endpoint", err)
	}

	var options []grpc.DialOption
	if endpoint.Scheme == "grpcs" {
		options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}
	conn, err := grpc.NewClient(endpoint.Host, options...)
	if err != nil {
		log.Fatalln("did not connect", err)
	}
	defer conn.Close()

	cli := kms.NewKMSServiceClient(conn)

	operation := flag.Arg(0)
	if operation == "unseal-bytes" {
		unsealStdin(ctx, cli)
		return
	}

	luks := luks.New(luks.AESXTSPlain64Cipher)

	if kmsFlags.device == "" {
		log.Fatalln("device is required")
	}

	switch operation {
	case "open":
		if kmsFlags.mappedName == "" {
			log.Fatalln("a name for the device mapper device is required")
		}
		open(ctx, cli, luks, kmsFlags.device, kmsFlags.slot, kmsFlags.mappedName)
	case "unseal-device":
		unsealDevice(ctx, cli, luks, kmsFlags.device, kmsFlags.slot)
	case "seal":
		if kmsFlags.slot == existingKeySlot {
			log.Fatalln("an existing key is expected at slot", existingKeySlot)
		}
		seal(ctx, cli, luks, kmsFlags.device, kmsFlags.slot)
	default:
		log.Fatalln("unknown operation", operation)
	}
}
