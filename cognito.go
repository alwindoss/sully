package sully

import (
	"context"
	"fmt"
	"time"

	"github.com/alwindoss/sully/srp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// Config is the configuration that needs to be provided to the factory functon NewCognitoClient
type Config struct {
	UserPoolID     string
	IdentityPoolID string
	ClientID       string
	Region         string
}

// Cognito is
type Cognito interface {
	FetchOpenIDToken(userName, password string) (string, error)
}

func isEmpty(strs ...string) bool {
	for _, s := range strs {
		if s == "" {
			return true
		}
	}
	return false
}

// NewCognitoClient is a factory to create the cognito client
// if the nil config is not provided or any of the fields in the config are not set then a nil object would ne returned
func NewCognitoClient(cfg *Config) Cognito {
	client := &awsCognito{}
	if cfg == nil || isEmpty(cfg.UserPoolID, cfg.ClientID, cfg.IdentityPoolID, cfg.Region) {
		return nil
	}
	client.clientID = cfg.ClientID
	client.userPoolID = cfg.UserPoolID
	client.region = cfg.Region
	client.identityPoolID = cfg.IdentityPoolID
	return client
}

type awsCognito struct {
	userPoolID     string
	clientID       string
	userName       string
	password       string
	region         string
	identityPoolID string
}

// FetchOpenIDToken function is used to authenticate users against AWS Cognito
func (c *awsCognito) FetchOpenIDToken(userName, password string) (string, error) {
	ctx := context.Background()
	csrp, err := srp.NewCognitoSRP(userName, password, c.userPoolID, c.clientID, nil)
	if err != nil {
		return "", fmt.Errorf("unable to create a SRP Client: %w", err)
	}
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return "", fmt.Errorf("unable to load default AWS Config: %w", err)
	}
	cfg.Region = c.region
	cfg.Credentials = aws.AnonymousCredentials
	svc := cip.New(cfg)

	// initiate auth
	req := svc.InitiateAuthRequest(&cip.InitiateAuthInput{
		AuthFlow:       cip.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
	})
	resp, err := req.Send(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to send InitiateAuthRequest: %w", err)
	}
	var token string
	// respond to password verifier challenge
	if resp.ChallengeName == cip.ChallengeNameTypePasswordVerifier {
		challengeResponses, _ := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())
		chal := svc.RespondToAuthChallengeRequest(&cip.RespondToAuthChallengeInput{
			ChallengeName:      cip.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
			ClientId:           aws.String(csrp.GetClientId()),
		})
		resp, err := chal.Send(ctx)
		if err != nil {
			return "", fmt.Errorf("unable to respond to auth challenge: %w", err)
		}

		// print the tokens
		fmt.Println(resp.AuthenticationResult)
		idn := cognitoidentity.New(cfg)
		loginKey := "cognito-idp." + c.region + ".amazonaws.com/" + c.userPoolID
		idToken := aws.StringValue(resp.AuthenticationResult.IdToken)
		loginMap := map[string]string{
			loginKey: idToken,
		}
		getIDInput := &cognitoidentity.GetIdInput{
			IdentityPoolId: aws.String(c.identityPoolID),
			Logins:         loginMap,
		}
		getIDReq := idn.GetIdRequest(getIDInput)
		out, err := getIDReq.Send(ctx)
		if err != nil {
			return "", fmt.Errorf("unable to send GetIDRequest: %w", err)
		}
		getOpenIDTokenInput := &cognitoidentity.GetOpenIdTokenInput{
			IdentityId: out.IdentityId,
			Logins:     loginMap,
		}
		getOpenIDTokenReq := idn.GetOpenIdTokenRequest(getOpenIDTokenInput)
		openIDOut, err := getOpenIDTokenReq.Send(ctx)
		if err != nil {
			return "", fmt.Errorf("unable to send GetOpenIDTokenRequest: %w", err)
		}
		token = aws.StringValue(openIDOut.Token)
		return token, nil
	}
	return token, fmt.Errorf("Challenge %s is not handled", resp.ChallengeName)
}
