#!/bin/bash
set -e

# Create directories if they don't exist
mkdir -p /app/config /app/reports

# Copy default config files if they don't exist
if [ ! -f /app/config/rules.yaml ]; then
    echo "Creating default rules.yaml..."
    cp /app/config-defaults/rules.yaml /app/config/rules.yaml
fi

if [ ! -f /app/config/exceptions.yaml ]; then
    echo "Creating default exceptions.yaml..."
    cp /app/config-defaults/exceptions.yaml /app/config/exceptions.yaml
fi

# Execute the command passed to the container
exec "$@"
