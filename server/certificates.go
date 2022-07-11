package main

import "go.mongodb.org/mongo-driver/mongo"

var certificates *mongo.Collection

type Certificate struct {
	Id          string `bson:"id"`
	Description string `bson:"description"`
	Creator     string `bson:"creator"`
	Owner       string `bson:"temperature"`
}
