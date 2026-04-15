#!/bin/bash
set -e

echo "Setting up ShieldSentinel..."

# Copy env file
if [ ! -f .env ]; then
    cp .env.example .env
    echo ".env created — fill in your API keys before starting"
fi

# Generate secrets
JWT_SECRET=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)
sed -i.bak "s/change_this_to_random_64_char_string/$JWT_SECRET/" .env
rm -f .env.bak

echo "Setup complete. Next steps:"
echo "1. Edit .env and add your API keys"
echo "2. Start the platform: ./start.sh"
echo "3. Open http://localhost in your browser"
