#!/bin/bash

# Define the metadata URL with the specific role name
METADATA_URL="http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Get the security credentials
CREDENTIALS_JSON=$(curl -s $METADATA_URL)

# Debugging output for credentials JSON
echo "Retrieved credentials JSON: $CREDENTIALS_JSON"

# Check if the credentials were retrieved successfully
if [ -z "$CREDENTIALS_JSON" ]; then
  echo "Error: Unable to retrieve security credentials."
  exit 1
fi

# Extracting the individual credentials
ACCESS_KEY_ID=$(echo $CREDENTIALS_JSON | jq -r '.AccessKeyId')
SECRET_ACCESS_KEY=$(echo $CREDENTIALS_JSON | jq -r '.SecretAccessKey')
SESSION_TOKEN=$(echo $CREDENTIALS_JSON | jq -r '.Token')

# Debugging output for extracted credentials
echo "Access Key ID: $ACCESS_KEY_ID"
echo "Secret Access Key: $SECRET_ACCESS_KEY"
echo "Session Token: $SESSION_TOKEN"

# Check if credentials are non-empty
if [ -z "$ACCESS_KEY_ID" ] || [ -z "$SECRET_ACCESS_KEY" ] || [ -z "$SESSION_TOKEN" ]; then
  echo "Error: Retrieved credentials are incomplete."
  exit 1
fi

# Exporting the credentials as environment variables
export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
export AWS_SESSION_TOKEN=$SESSION_TOKEN

# Confirming the credentials have been set
echo "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
echo "AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN"

echo "AWS credentials have been set successfully."


run this with source 
source ./set_aws_credentials_from_metadata.sh
install jq
