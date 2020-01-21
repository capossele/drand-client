package client

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/drand/drand/beacon"
	"github.com/drand/drand/key"
	pb "github.com/drand/drand/protobuf/drand"
	"google.golang.org/grpc"
)

func isValid(d *verifyData) error {
	pub, err := hex.DecodeString(d.public)
	if err != nil {
		return err
	}
	pubPoint := key.KeyGroup.Point()
	if err := pubPoint.UnmarshalBinary(pub); err != nil {
		return err
	}
	sig, err := hex.DecodeString(d.signature)
	if err != nil {
		return err
	}
	prev, err := hex.DecodeString(d.previous)
	if err != nil {
		return err
	}
	msg := beacon.Message(prev, uint64(d.round))
	if err := key.Scheme.VerifyRecovered(pubPoint, msg, sig); err != nil {
		return err
	}
	invMsg := beacon.Message(prev, uint64(d.round-1))
	if err := key.Scheme.VerifyRecovered(pubPoint, invMsg, sig); err == nil {
		return errors.New("should be invalid signature")
	}

	hash := sha512.New()
	_, err = hash.Write(sig)
	if err != nil {
		return err
	}
	randExpected := hash.Sum(nil)
	if !bytes.Equal(randExpected, d.randomness) {
		return errors.New("invalid randomness")
	}

	return nil
}

// Data of signing
type verifyData struct {
	public     string
	signature  string
	round      int
	previous   string
	randomness []byte
}

type Randomness struct {
	Index int
	Value []byte
}

type Client struct {
	conn *grpc.ClientConn
	API  pb.PublicClient
	Addr string
}

func (c *Client) Close() {
	defer c.conn.Close()
}

func New(address string) (*Client, error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Printf("did not connect: %v", err)
		return nil, err
	}

	c := pb.NewPublicClient(conn)

	return &Client{
		conn: conn,
		API:  c,
	}, nil
}

func GetDistKey(client *Client) (string, error) {
	var key string

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	distKey, err := client.API.DistKey(ctx, &pb.DistKeyRequest{})
	if err != nil {
		log.Printf("could not get distributed key: %v", err)
		return key, err
	}

	return hex.EncodeToString(distKey.GetKey()), nil
}

func GetRandomness(client *Client, distKey string) (*Randomness, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := client.API.PublicRand(ctx, &pb.PublicRandRequest{})
	if err != nil {
		log.Printf("could not get public randomness: %v", err)
		return nil, err
	}

	data := &verifyData{
		public:     distKey,
		signature:  hex.EncodeToString(r.GetSignature()),
		round:      int(r.GetRound()),
		previous:   hex.EncodeToString(r.GetPrevious()),
		randomness: r.GetRandomness(),
	}

	if err := isValid(data); err != nil {
		log.Println("Invalid Random Number")
		return nil, err
	}

	return &Randomness{Index: data.round, Value: data.randomness}, nil
}
