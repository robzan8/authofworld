package main

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
)

var certificates *mongo.Collection

type Certificate struct {
	Id          string `bson:"_id"`
	Description string `bson:"description"`
	Creator     string `bson:"creator"`
	Owner       string `bson:"owner"`
}

func CreateCertificates(n int, creator, desc string) error {
	certs := make([]interface{}, n)
	for i := range certs {
		id, err := GenerateId()
		if err != nil {
			return err
		}
		certs[i] = Certificate{
			Id:          id,
			Description: desc,
			Creator:     creator,
			Owner:       creator,
		}
	}
	_, err := certificates.InsertMany(context.TODO(), certs)
	return err
}
