package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/amazon-ecs-agent/agent/credentials"
	"github.com/aws/amazon-ecs-agent/agent/credentials/instancecreds"
	"github.com/aws/amazon-ecs-agent/agent/handlers/utils"
)

const (
	externalCredentialsMuxName       = "externalCredentialsId"
	requestTypeExternalInstanceCreds = "external instance credentials"
)

var ExternalInstanceCredentialsFullPath = credentials.ExternalInstanceCredsPath + "/" + utils.ConstructMuxVar(externalCredentialsMuxName, utils.AnythingRegEx)

func ExternalInstanceCredentialsHandler(credentialsManager credentials.Manager) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := validateIdFromRequest(r, credentialsManager)
		if err != nil {
			writeErrorResponse(w, http.StatusBadRequest, err)
			return
		}
		creds, err := getCredentials()
		if err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, err)
			return
		}
		credentialsJSON, err := json.Marshal(creds)
		if e := utils.WriteResponseIfMarshalError(w, err); e != nil {
			return
		}
		utils.WriteJSONToResponse(w, http.StatusOK, credentialsJSON, requestTypeExternalInstanceCreds)
	}
}

func writeErrorResponse(w http.ResponseWriter, code int, err error) {
	errResponseJSON, err := json.Marshal(fmt.Sprintf("error retrieving instance credentials: %v", err.Error()))
	if e := utils.WriteResponseIfMarshalError(w, err); e != nil {
		return
	}
	utils.WriteJSONToResponse(w, code, errResponseJSON, requestTypeExternalInstanceCreds)
}

func validateIdFromRequest(r *http.Request, credentialsManager credentials.Manager) error {
	id, ok := utils.GetMuxValueFromRequest(r, externalCredentialsMuxName)
	if !ok {
		return errors.New("could not parse request credentials id")
	}
	validated := credentialsManager.ValidateExternalCredentialsId(id)
	if id == "" || !validated {
		return errors.New("invalid external credentials id")
	}
	return nil
}

func getCredentials() (credentials.IAMRoleCredentials, error) {
	creds := instancecreds.GetCredentials()
	credsValue, err := creds.Get()
	if err != nil {
		return credentials.IAMRoleCredentials{}, err
	}
	expires := time.Now().Add(time.Minute)
	return credentials.IAMRoleCredentials{
		AccessKeyID:     credsValue.AccessKeyID,
		SecretAccessKey: credsValue.SecretAccessKey,
		SessionToken:    credsValue.SessionToken,
		Expiration:      expires.Format(time.RFC3339Nano),
	}, nil
}
