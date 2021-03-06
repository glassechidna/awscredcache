package awscredcache

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/glassechidna/awscredcache/sneakyvendor/aws-shared-defaults"
	"github.com/go-ini/ini"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const AwscredcacheProvider = "AwscredcacheProvider"

type AwsCacheCredProvider struct {
	MfaCodeProvider func(string) (string, error)
	Duration        time.Duration
	profile         string
	cfg             awsConfigFiles
}

func NewAwsCacheCredProvider(profile string) *AwsCacheCredProvider {
	return &AwsCacheCredProvider{
		profile:  profile,
		cfg:      loadConfig(),
		Duration: 12 * 3600 * time.Second,
		MfaCodeProvider: func(_ string) (string, error) {
			return stscreds.StdinTokenProvider()
		},
	}
}

func (p *AwsCacheCredProvider) Retrieve() (credentials.Value, error) {
	cfg, err := p.getProfileConfig(p.profile)
	if err != nil {
		return credentials.Value{ProviderName: AwscredcacheProvider}, err
	}

	return cfg.Credentials, nil
}

func (p *AwsCacheCredProvider) IsExpired() bool {
	return false
}

func (p *AwsCacheCredProvider) Region() string {
	return p.getRegion(p.profile)
}

func (p *AwsCacheCredProvider) WrapInChain() credentials.Provider {
	def := defaults.Get()

	// this is stolen from the aws sdk
	return &credentials.ChainProvider{
		VerboseErrors: aws.BoolValue(def.Config.CredentialsChainVerboseErrors),
		Providers: []credentials.Provider{
			&credentials.EnvProvider{},
			p,
			&credentials.SharedCredentialsProvider{Filename: "", Profile: ""},
			defaults.RemoteCredProvider(*def.Config, def.Handlers),
		},
	}
}

type awsConfigFiles struct {
	cfg  *ini.File
	cred *ini.File
}

type profileConfig struct {
	Name        string
	Region      string
	Credentials credentials.Value
}

func (p *AwsCacheCredProvider) getRegion(profile string) string {
	section, err := p.cfg.cfg.GetSection(fmt.Sprintf("profile %s", profile))
	if err != nil {
		section, err = p.cfg.cfg.GetSection(profile)
		if err != nil {
			return ""
		}
	}

	return section.Key("region").String()
}

func (p *AwsCacheCredProvider) getProfileConfig(profile string) (*profileConfig, error) {
	section, err := p.cfg.cfg.GetSection(fmt.Sprintf("profile %s", profile))
	if err != nil {
		section, err = p.cfg.cfg.GetSection(profile)
		if err != nil {
			return nil, err
		}
	}

	region := p.getRegion(profile)

	sourceProfile, err := section.GetKey("source_profile")
	hasSourceProfile := err == nil

	if hasSourceProfile {
		sourceProfileName := sourceProfile.String()
		sourceConfig, err := p.getProfileConfig(sourceProfileName)
		if err != nil {
			return nil, err
		}

		sourceRegion := sourceConfig.Region
		if len(region) == 0 {
			region = sourceRegion
		}

		roleArn := section.Key("role_arn").String()
		if len(roleArn) == 0 {
			return nil, errors.New("empty role arn")
		}

		roleCreds, err := roleCredentials(sourceConfig.Credentials, roleArn, profile)
		if err != nil {
			return nil, err
		}

		return &profileConfig{
			Name:        profile,
			Region:      region,
			Credentials: roleCreds,
		}, nil
	} else {
		credsSection, err := p.cfg.cred.GetSection(profile)
		if err != nil {
			return nil, err
		}

		id := credsSection.Key("aws_access_key_id").String()
		secret := credsSection.Key("aws_secret_access_key").String()
		token := credsSection.Key("aws_session_token").String()

		if len(id) == 0 {
			return nil, errors.New("empty access key id")
		}
		if len(secret) == 0 {
			return nil, errors.New("empty secret access key")
		}
		creds := credentials.Value{
			ProviderName:    AwscredcacheProvider,
			AccessKeyID:     id,
			SecretAccessKey: secret,
			SessionToken:    token,
		}

		mfaSerial := section.Key("mfa_serial").String()
		if len(mfaSerial) > 0 {
			mfaSecret := credsSection.Key("mfa_secret").String()
			mfaCode := func() string { s, _ := p.MfaCodeProvider(mfaSecret); return s }

			creds, err = mfaAuthenticatedCredentials(creds, mfaSerial, mfaCode, p.Duration)
			if err != nil {
				return nil, err
			}
		}

		return &profileConfig{
			Name:        profile,
			Region:      region,
			Credentials: creds,
		}, nil
	}
}

func stsApiWithCreds(sourceCreds credentials.Value) stsiface.STSAPI {
	static := credentials.NewStaticCredentials(
		sourceCreds.AccessKeyID,
		sourceCreds.SecretAccessKey,
		sourceCreds.SessionToken,
	)

	config := &aws.Config{Credentials: static}
	if len(os.Getenv("AWSCREDCACHE_VERBOSE")) > 0 {
		config.LogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody)
	}

	sess := session.Must(session.NewSession(config))
	return sts.New(sess)
}

func roleCredentials(sourceCreds credentials.Value, roleArn, profile string) (credentials.Value, error) {
	api := stsApiWithCreds(sourceCreds)

	roleSessionName := fmt.Sprintf("%s-%d", profile, time.Now().Second())
	resp, err := api.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: &roleSessionName,
	})
	if err != nil {
		return credentials.Value{ProviderName: AwscredcacheProvider}, err
	}

	c := resp.Credentials
	return credentials.Value{
		ProviderName:    AwscredcacheProvider,
		AccessKeyID:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
	}, nil
}

func loadConfig() awsConfigFiles {
	cfgIni, _ := ini.Load(shareddefaults.SharedConfigFilename())
	credIni, _ := ini.Load(shareddefaults.SharedCredentialsFilename())
	return awsConfigFiles{cfg: cfgIni, cred: credIni}
}

type cachedSessionTokenResponse struct {
	MfaSerialNumber string
	Credentials     struct {
		AccessKeyId     string
		SecretAccessKey string
		SessionToken    string
		Expiration      time.Time
	}
	ResponseMetadata struct {
		RetryAttempts  int
		HTTPStatusCode int
		RequestId      string
		HTTPHeaders    map[string]string
	}
}

func mfaAuthenticatedCredentials(sourceCreds credentials.Value, mfaSerial string, mfaCode func() string, duration time.Duration) (credentials.Value, error) {
	api := stsApiWithCreds(sourceCreds)

	cached := cachedMfaAuthenticatedCredentials(mfaSerial)

	if cached == nil {
		firstAttempt := true
	tryagain:

		code := mfaCode()
		input := &sts.GetSessionTokenInput{
			SerialNumber:    &mfaSerial,
			TokenCode:       &code,
			DurationSeconds: aws.Int64(int64(duration.Seconds())),
		}

		statusCode := 0
		requestId := ""
		headers := map[string]string{}

		resp, err := api.GetSessionTokenWithContext(context.Background(), input, func(r *request.Request) {
			r.Handlers.Complete.PushBack(func(req *request.Request) {
				statusCode = req.HTTPResponse.StatusCode
				requestId = req.RequestID

				for key, val := range req.HTTPResponse.Header {
					headers[key] = val[0]
				}
			})
		})
		if err != nil {
			if err, ok := err.(awserr.Error); ok {
				if firstAttempt && strings.Contains(err.Message(), "MultiFactorAuthentication failed with invalid MFA one time pass code") {
					timeSinceWindowStarted := time.Now().Second() % 30
					waitTime := 35 - timeSinceWindowStarted
					fmt.Fprintf(os.Stderr, "Access denied due to 'incorrect MFA code'. This can happen when the same code is used twice in a 30 second window. Waiting %d seconds and trying again.\n", waitTime)
					time.Sleep(time.Second * time.Duration(waitTime))
					firstAttempt = false
					goto tryagain
				}

				fmt.Fprintln(os.Stderr, "Second attempt also failed. Error is not due to MFA code reuse.")
			}

			return credentials.Value{ProviderName: AwscredcacheProvider}, err
		}

		c := resp.Credentials

		cached = &cachedSessionTokenResponse{
			MfaSerialNumber: mfaSerial,
			Credentials: struct {
				AccessKeyId     string
				SecretAccessKey string
				SessionToken    string
				Expiration      time.Time
			}{
				AccessKeyId:     *c.AccessKeyId,
				SecretAccessKey: *c.SecretAccessKey,
				SessionToken:    *c.SessionToken,
				Expiration:      time.Now().Add(time.Hour),
			},
			ResponseMetadata: struct {
				RetryAttempts  int
				HTTPStatusCode int
				RequestId      string
				HTTPHeaders    map[string]string
			}{
				RetryAttempts:  0,
				HTTPStatusCode: statusCode,
				RequestId:      requestId,
				HTTPHeaders:    headers,
			},
		}

		cachedBytes, _ := json.MarshalIndent(cached, "", "  ")
		path := cachePathForMfaSerial(mfaSerial)
		ioutil.WriteFile(path, cachedBytes, 0600)
	}

	c := cached.Credentials
	return credentials.Value{
		ProviderName:    AwscredcacheProvider,
		AccessKeyID:     c.AccessKeyId,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
	}, nil
}

func cachedMfaAuthenticatedCredentials(mfaSerial string) *cachedSessionTokenResponse {
	path := cachePathForMfaSerial(mfaSerial)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}

	resp := cachedSessionTokenResponse{}
	err = json.Unmarshal(bytes, &resp)
	if err != nil {
		return nil
	}

	if resp.Credentials.Expiration.Before(time.Now()) {
		return nil
	}

	return &resp
}

func cachePathForMfaSerial(mfaSerial string) string {
	dir := filepath.Join(shareddefaults.UserHomeDir(), ".aws", "awswebcache")

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0755)
	}

	// make name filesystem-friendly
	mfaSerial = strings.Replace(mfaSerial, ":", "-", -1)
	mfaSerial = strings.Replace(mfaSerial, "/", "-", -1)

	return filepath.Join(dir, mfaSerial) + ".json"
}
