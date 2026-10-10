#!/usr/bin/env bash
# Deploy the EASA cloud security service to Google Cloud Run, Seoul region.
#
# Prereqs: gcloud CLI authenticated; billing enabled (free tier covers the experiment volume;
#          min-instances=1 is the only paid component, ~USD 0.3-0.5/day while experiments run).
# Usage:   EASA_API_KEY=$(openssl rand -hex 24) ./deploy.sh <gcp-project-id>
#
# AWS alternative (Seoul = ap-northeast-2): wrap app.py with Mangum and deploy to Lambda + API Gateway,
# or deploy this same container to App Runner. Only base_url changes on the client side.
set -euo pipefail

PROJECT="${1:?usage: deploy.sh <gcp-project-id>}"
REGION="asia-northeast3"          # Seoul
SERVICE="easa-cloud"
: "${EASA_API_KEY:?set EASA_API_KEY in the environment (keep it out of git)}"

gcloud config set project "$PROJECT"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com

gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 1 --max-instances 1 \
  --cpu 1 --memory 512Mi \
  --concurrency 80 \
  --set-env-vars "EASA_API_KEY=${EASA_API_KEY},EASA_MIN_GATEWAYS=3,EASA_FEDAVG_WEIGHTING=samples"
# EASA_MIN_GATEWAYS = topology.n_gateways: the cloud aggregates only when every gateway has pushed its model.

URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format 'value(status.url)')
echo
echo "Deployed: $URL"
echo "Health:   $(curl -s "$URL/health")"
echo
echo "Next: python scripts/run_experiments.py --set cloud.base_url=$URL"
echo "Tear down when done:  gcloud run services delete $SERVICE --region $REGION"
