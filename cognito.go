package sully

// Cognito is
type Cognito interface {
	Authenticate(userName, password string)
}

// NewCognitoClient is a factory to create the cognito client
func NewCognitoClient(userPoolID, clientID string) Cognito {
	client := &awsCognito{}
	if userPoolID == "" || clientID == "" {
		panic("userPoolID and clientID are mandatory")
	}
	client.clientID = clientID
	client.userPoolID = userPoolID
	return client
}

type awsCognito struct {
	userPoolID string
	clientID   string
	userName   string
	password   string
}

// Authenticate function is used to authenticate users against AWS Cognito
func (c *awsCognito) Authenticate(userName, password string) {

}
