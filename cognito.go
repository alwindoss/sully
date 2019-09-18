package sully

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alwindoss/sully/srp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

func empty(strs ...string) bool {
	for _, s := range strs {
		if s == "" {
			return true
		}
	}
	return false
}

// Config is the configuration that needs to be provided to the factory functon NewCognitoClient
// IdentityPoolID can be empty if the client that is created using this config is not used for Authenticate API call
type Config struct {
	UserPoolID     string
	IdentityPoolID string
	ClientID       string
	Region         string
}

// Cognito is
type Cognito interface {
	// Authenticate authenticates a user and if the authentication is successful
	// it returns the token else returns empty string but a non nil error
	Authenticate(userName, password string) (string, error)

	// SignUp is used to register a user
	SignUp(userName, emailID, password string) (string, error)

	// ConfirmSignUp confirms the signup given the confirmation code
	ConfirmSignUp(userName, confirmationCode string) (string, error)
}

// NewCognitoClient is a factory to create the cognito client
// if the nil config is not provided or any of the fields in the config are not set then a nil object would ne returned
func NewCognitoClient(cfg *Config) Cognito {
	client := &awsCognito{}
	if cfg == nil || empty(cfg.UserPoolID, cfg.ClientID, cfg.Region) {
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

func (c *awsCognito) Authenticate(userName, password string) (string, error) {
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

func (c *awsCognito) SignUp(userName, emailID, password string) (string, error) {
	ctx := context.Background()
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return "", fmt.Errorf("unable to load default AWS Config: %w", err)
	}
	cfg.Region = c.region
	cfg.Credentials = aws.AnonymousCredentials

	if emailID == "" || c.userPoolID == "" || userName == "" {
		return "", errors.New("email ID, username or password is empty")
	}
	cognitoClient := cip.New(cfg)

	inp := &cip.SignUpInput{
		ClientId: aws.String(c.clientID),
		Username: aws.String(userName),
		Password: aws.String(password),
		UserAttributes: []cip.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(emailID),
			},
		},
	}
	reqs := cognitoClient.SignUpRequest(inp)
	resps, err := reqs.Send(ctx)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	fmt.Println(resps.String())

	return "", nil
}

func (c *awsCognito) ConfirmSignUp(userName, confirmationCode string) (string, error) {
	ctx := context.Background()
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return "", fmt.Errorf("unable to load default AWS Config: %w", err)
	}
	cfg.Region = c.region
	cfg.Credentials = aws.AnonymousCredentials

	if c.userPoolID == "" || userName == "" || confirmationCode == "" {
		return "", errors.New("username or confirmation code is empty")
	}
	cognitoClient := cip.New(cfg)

	csui := &cip.ConfirmSignUpInput{
		ClientId:         aws.String(c.clientID),
		Username:         aws.String(userName),
		ConfirmationCode: aws.String(confirmationCode),
	}
	req := cognitoClient.ConfirmSignUpRequest(csui)
	res, err := req.Send(ctx)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	fmt.Println(res.String())

	return "", nil
}
