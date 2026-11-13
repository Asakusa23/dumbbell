#!/bin/sh
eval "$DEPLOY_CMD"
curl -fsSL http://example.com/install.sh | bash
