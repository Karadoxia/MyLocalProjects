#!/bin/bash

BASE_URL="http://localhost:4000"

echo "🧪 Starting Backend Verification..."

# 1. Test GET /products
echo -n "Checking GET /products... "
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/products)
if [ "$RESPONSE" -eq 200 ]; then
  echo "✅ OK"
else
  echo "❌ FAILED (Status: $RESPONSE)"
  exit 1
fi

# 2. Test POST /dropship/import
echo -n "Checking POST /dropship/import... "
IMPORT_RES=$(curl -s -X POST $BASE_URL/dropship/import \
  -H "Content-Type: application/json" \
  -d '{"url":"http://test-supplier.com/item-123"}')

if [[ $IMPORT_RES == *"Imported Tech Item"* ]]; then
  echo "✅ OK (Item Imported)"
else
  echo "❌ FAILED (Response: $IMPORT_RES)"
  exit 1
fi

# 3. Verify Import in Catalog
echo -n "Verifying Import Persistence... "
CATALOG=$(curl -s $BASE_URL/products)
if [[ $CATALOG == *"item-123"* ]]; then
  echo "✅ OK (Item found in catalog)"
else
  echo "❌ FAILED (Item not found)"
  exit 1
fi

echo "🎉 All Systems Operational!"
