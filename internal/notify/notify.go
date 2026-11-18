// Package notify publishes real-time events. The API never blocks on it:
// a failed publish is logged and the money movement still stands.
package notify

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// Event is delivered to every open device of every user in UserIDs.
// Clients decide what to show: if ToUserID is me and FromUserID is not, it is incoming money.
type Event struct {
	Type          string    `json:"type"` // deposit | withdrawal | transfer
	UserIDs       []string  `json:"user_ids"`
	TransactionID string    `json:"transaction_id"`
	Amount        int64     `json:"amount"` // minor units
	Note          string    `json:"note,omitempty"`
	FromUserID    string    `json:"from_user_id,omitempty"`
	FromName      string    `json:"from_name,omitempty"`
	FromHandle    string    `json:"from_handle,omitempty"`
	ToUserID      string    `json:"to_user_id,omitempty"`
	ToName        string    `json:"to_name,omitempty"`
	ToHandle      string    `json:"to_handle,omitempty"`
	At            time.Time `json:"at"`
}

type Notifier interface {
	Publish(ctx context.Context, e Event) error
}

// Log is the default for local development.
type Log struct{}

func (Log) Publish(_ context.Context, e Event) error {
	b, _ := json.Marshal(e)
	log.Printf("event: %s", b)
	return nil
}

// SNS publishes to an SNS topic; a Lambda subscribed to it pushes to WebSocket clients.
type SNS struct {
	client *sns.Client
	topic  string
}

func NewSNS(ctx context.Context, topicARN string) (*SNS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &SNS{client: sns.NewFromConfig(cfg), topic: topicARN}, nil
}

func (s *SNS) Publish(ctx context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.client.Publish(ctx, &sns.PublishInput{TopicArn: aws.String(s.topic), Message: aws.String(string(b))})
	return err
}
